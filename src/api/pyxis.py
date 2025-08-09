"""Pyxis API client for Red Hat container catalog."""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlencode

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..config import config

logger = logging.getLogger(__name__)


class PyxisAPIError(Exception):
    """Custom exception for Pyxis API errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class PyxisClient:
    """Client for interacting with Red Hat Pyxis container catalog API."""
    
    def __init__(self, base_url: Optional[str] = None, timeout: Optional[int] = None):
        self.base_url = base_url or config.PYXIS_BASE_URL
        self.timeout = timeout or config.REQUEST_TIMEOUT
        self.headers = config.get_pyxis_headers()
        
        # Configure requests session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=config.MAX_RETRIES,
            backoff_factor=config.RETRY_BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(self.headers)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()
    
    def _build_url(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Build full URL with optional query parameters."""
        url = urljoin(self.base_url, endpoint)
        if params:
            # Filter out None values
            filtered_params = {k: v for k, v in params.items() if v is not None}
            if filtered_params:
                url += "?" + urlencode(filtered_params)
        return url
    
    def _make_request(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make HTTP request to Pyxis API with enhanced error handling."""
        url = self._build_url(endpoint, params)
        
        try:
            logger.debug(f"Making request to: {url}")
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Check if response is actually JSON
            content_type = response.headers.get('content-type', '')
            if not content_type.startswith('application/json'):
                error_msg = f"API returned {content_type} instead of JSON for {url}. This suggests the API is not publicly accessible or requires authentication."
                logger.error(error_msg)
                raise PyxisAPIError(error_msg, response.status_code)
            
            try:
                data = response.json()
                logger.debug(f"Received {len(data.get('data', []))} items")
                return data
            except ValueError as e:
                error_msg = f"Invalid JSON response from {url}: {str(e)}"
                logger.error(error_msg)
                raise PyxisAPIError(error_msg, response.status_code)
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error {e.response.status_code} for {url}"
            
            # Handle specific 404 errors with helpful suggestions
            if e.response.status_code == 404:
                if "products" in endpoint:
                    error_msg += " (Note: The 'products' endpoint may not exist. Try 'repositories' or 'product-listings' instead)"
                else:
                    error_msg += f" (Endpoint '{endpoint}' not found)"
            
            try:
                error_data = e.response.json()
                error_msg += f": {error_data.get('detail', 'Unknown error')}"
            except ValueError:
                error_msg += f": {e.response.text[:200]}..."
            
            logger.error(error_msg)
            raise PyxisAPIError(error_msg, e.response.status_code, getattr(e.response, 'json', lambda: None)())
        
        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed for {url}: {str(e)}"
            logger.error(error_msg)
            raise PyxisAPIError(error_msg)
    
    def search_products(self, name_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for products in the catalog using repositories and product-listings."""
        # Try multiple approaches to find products
        all_results = []
        
        # Strategy 1: Search repositories for OpenShift AI related content
        repo_results = self._search_repositories(name_filter, limit)
        all_results.extend(repo_results)
        
        # Strategy 2: Search product-listings if repositories don't yield results
        if not repo_results and name_filter:
            listing_results = self._search_product_listings(name_filter, limit)
            all_results.extend(listing_results)
        
        # Deduplicate results
        unique_results = {}
        for result in all_results:
            result_id = result.get("_id") or result.get("id")
            if result_id and result_id not in unique_results:
                unique_results[result_id] = result
        
        return list(unique_results.values())[:limit]
    
    def _search_repositories(self, name_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Search repositories for container products with fallback strategies."""
        # Try different endpoint paths that might work
        endpoints_to_try = [
            ("repositories", {"repository": name_filter}),
            ("images", {"registry": "registry.redhat.io"}),
            ("images", {"name": name_filter}) if name_filter else ("images", {}),
        ]
        
        for endpoint, filter_params in endpoints_to_try:
            try:
                params = {
                    "page_size": min(limit, 20),  # Reduce to avoid large responses
                    "page": 0,
                }
                
                # Add filters based on what we're trying (using correct RSQL syntax)
                for key, value in filter_params.items():
                    if value and key == "repository":
                        params["filter"] = f"repository==\"*{value.lower()}*\""
                    elif value and key == "name":
                        params["filter"] = f"name==\"*{value.lower()}*\""
                    elif value and key == "registry":
                        params["filter"] = f"repositories.registry==\"*{value}*\""
                
                logger.debug(f"Trying endpoint '{endpoint}' with params: {params}")
                response = self._make_request(endpoint, params)
                
                # Check if we got actual JSON data
                if isinstance(response, dict) and "data" in response:
                    repositories = response.get("data", [])
                    logger.info(f"Successfully found {len(repositories)} items from {endpoint}")
                    return repositories
                    
            except PyxisAPIError as e:
                logger.debug(f"Endpoint '{endpoint}' failed: {e}")
                continue
        
        logger.warning(f"All repository search strategies failed for filter: {name_filter}")
        return []
    
    def _search_product_listings(self, name_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Search product listings for products."""
        params = {
            "page_size": limit,
            "page": 0,
        }
        
        if name_filter:
            params["filter"] = f"name==\"*{name_filter}*\""
        
        try:
            response = self._make_request("product-listings", params)
            listings = response.get("data", [])
            logger.debug(f"Found {len(listings)} product listings matching filter: {name_filter}")
            return listings
        except PyxisAPIError:
            logger.warning(f"Failed to search product listings with filter: {name_filter}")
            return []
    
    def get_openshift_ai_products(self) -> List[Dict[str, Any]]:
        """Get OpenShift AI related products with graceful degradation."""
        logger.info("Attempting to discover OpenShift AI products...")
        
        # Check if we should use mock data based on configuration
        if config.OFFLINE_MODE or config.USE_MOCK_DATA == "true":
            logger.info("Using mock data due to configuration settings.")
            return self._get_mock_openshift_ai_data()
        
        # If the API is completely inaccessible, provide mock data to keep the application running
        if not self.health_check():
            if config.USE_MOCK_DATA == "false":
                logger.error("Pyxis API is not accessible and mock data is disabled. Returning empty results.")
                return []
            else:
                logger.error("Pyxis API is not accessible. Returning mock data to prevent application failure.")
                return self._get_mock_openshift_ai_data()
        
        # Try different search terms for OpenShift AI with enhanced patterns
        search_terms = [
            "openshift-ai",     # Common repository naming pattern
            "rhoai",            # Red Hat OpenShift AI abbreviation
            "rhods",            # Red Hat OpenShift Data Science (predecessor)
            "data-science",     # Alternative naming
            "ai-platform",     # Generic AI platform terms
            "notebook",         # Common component in AI platforms
        ]
        
        all_products = []
        found_terms = []
        
        for term in search_terms:
            logger.debug(f"Searching for OpenShift AI products with term: {term}")
            try:
                products = self.search_products(term)
                if products:
                    found_terms.append(term)
                    all_products.extend(products)
                    logger.info(f"Found {len(products)} products for term '{term}'")
            except Exception as e:
                logger.warning(f"Search failed for term '{term}': {e}")
                continue
        
        # Deduplicate based on product ID
        unique_products = {}
        for product in all_products:
            product_id = product.get("_id") or product.get("id")
            if product_id and product_id not in unique_products:
                unique_products[product_id] = product
        
        result = list(unique_products.values())
        logger.info(f"Found {len(result)} unique OpenShift AI products using terms: {found_terms}")
        
        # If no products found, try broader container search
        if not result:
            logger.warning("No OpenShift AI products found with specific terms, trying broader search...")
            try:
                broader_results = self._search_openshift_containers()
                result.extend(broader_results)
            except Exception as e:
                logger.error(f"Broader search also failed: {e}")
        
        # Last resort - return mock data if nothing found
        if not result:
            logger.warning("No OpenShift AI products found via any method. Returning mock data.")
            result = self._get_mock_openshift_ai_data()
        
        return result
    
    def _get_mock_openshift_ai_data(self) -> List[Dict[str, Any]]:
        """Provide mock OpenShift AI data when API is unavailable."""
        mock_data = [
            {
                "_id": "mock-rhoai-1",
                "repository": "rhoai/workbench-images",
                "name": "Red Hat OpenShift AI Workbench Images",
                "description": "Mock data for OpenShift AI workbench container images",
                "mock_data": True,
                "last_updated": "2025-08-09T00:00:00Z"
            },
            {
                "_id": "mock-rhoai-2", 
                "repository": "rhoai/notebooks",
                "name": "Red Hat OpenShift AI Notebooks",
                "description": "Mock data for OpenShift AI notebook container images",
                "mock_data": True,
                "last_updated": "2025-08-09T00:00:00Z"
            }
        ]
        
        logger.info(f"Generated {len(mock_data)} mock OpenShift AI products")
        return mock_data
    
    def _search_openshift_containers(self) -> List[Dict[str, Any]]:
        """Search for OpenShift-related containers more broadly."""
        try:
            # Search for any OpenShift containers that might be AI-related
            params = {
                "page_size": 100,
                "page": 0,
                "filter": "repository==\"*openshift*\"",
                "include": "data.product_listings",
            }
            
            response = self._make_request("repositories", params)
            all_repos = response.get("data", [])
            
            # Filter for AI/ML/Data Science related containers
            ai_keywords = ["ai", "ml", "data-science", "notebook", "jupyter", "tensorflow", "pytorch"]
            ai_containers = []
            
            for repo in all_repos:
                repo_name = repo.get("repository", "").lower()
                if any(keyword in repo_name for keyword in ai_keywords):
                    ai_containers.append(repo)
            
            logger.info(f"Found {len(ai_containers)} AI-related OpenShift containers via broader search")
            return ai_containers
            
        except PyxisAPIError:
            logger.warning("Broader OpenShift container search also failed")
            return []
    
    def get_product_releases(self, product_id: str) -> List[Dict[str, Any]]:
        """Get releases for a specific product with mock data fallback."""
        # If this is mock data, return mock releases
        if product_id.startswith("mock-"):
            return self._get_mock_releases(product_id)
        
        params = {
            "filter": f"product_id=={product_id}",
            "page_size": 100,
            "sort_by": "release_date[desc]"
        }
        
        try:
            response = self._make_request("repositories", params)
            releases = response.get("data", [])
            logger.info(f"Found {len(releases)} releases for product {product_id}")
            return releases
        except PyxisAPIError:
            logger.warning(f"Failed to get releases for product: {product_id}. Returning mock data.")
            return self._get_mock_releases(product_id)
    
    def _get_mock_releases(self, product_id: str) -> List[Dict[str, Any]]:
        """Generate mock release data for a product."""
        mock_releases = [
            {
                "_id": f"mock-release-{product_id}-1",
                "product_id": product_id,
                "repository": "rhoai/workbench-images" if "rhoai-1" in product_id else "rhoai/notebooks",
                "release_name": "2.14.0",
                "release_date": "2024-11-15T00:00:00Z",
                "registry": "registry.redhat.io",
                "published": True,
                "mock_data": True
            },
            {
                "_id": f"mock-release-{product_id}-2", 
                "product_id": product_id,
                "repository": "rhoai/workbench-images" if "rhoai-1" in product_id else "rhoai/notebooks",
                "release_name": "2.13.0",
                "release_date": "2024-10-15T00:00:00Z",
                "registry": "registry.redhat.io",
                "published": True,
                "mock_data": True
            }
        ]
        
        logger.info(f"Generated {len(mock_releases)} mock releases for product {product_id}")
        return mock_releases
    
    def get_container_images(self, product_id: str, release_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get container images for a product and optional release version with mock data fallback."""
        # If this is mock data, return mock images
        if product_id.startswith("mock-"):
            return self._get_mock_images(product_id, release_version)
        
        params = {
            "filter": f"repositories.published==true",
            "include": "data.repositories,data.sum_security_status",
            "page_size": config.BATCH_SIZE,
            "page": 0
        }
        
        # Add product filter
        if product_id:
            if "filter" in params:
                params["filter"] += f";repositories.product_id=={product_id}"
            else:
                params["filter"] = f"repositories.product_id=={product_id}"
        
        # Add release version filter if specified
        if release_version:
            if "filter" in params:
                params["filter"] += f";repositories.release_name=={release_version}"
            else:
                params["filter"] = f"repositories.release_name=={release_version}"
        
        all_images = []
        page = 0
        
        while True:
            params["page"] = page
            try:
                response = self._make_request("images", params)
                images = response.get("data", [])
                
                if not images:
                    break
                
                all_images.extend(images)
                
                # Check if we've reached the maximum
                if len(all_images) >= config.MAX_IMAGES_PER_RELEASE:
                    logger.warning(f"Reached maximum image limit ({config.MAX_IMAGES_PER_RELEASE})")
                    break
                
                # Check pagination
                total_pages = response.get("total", 0) // config.BATCH_SIZE + 1
                if page >= total_pages - 1:
                    break
                
                page += 1
                
            except PyxisAPIError:
                logger.warning(f"Failed to get images page {page}")
                break
        
        if not all_images:
            logger.warning(f"No images found for product {product_id}. Returning mock data.")
            return self._get_mock_images(product_id, release_version)
        
        logger.info(f"Found {len(all_images)} container images")
        return all_images
    
    def _get_mock_images(self, product_id: str, release_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate mock container image data."""
        base_name = "workbench-images" if "rhoai-1" in product_id else "notebooks"
        version = release_version or "2.14.0"
        
        mock_images = [
            {
                "_id": f"mock-image-{product_id}-1",
                "architecture": "amd64",
                "repositories": [{
                    "product_id": product_id,
                    "registry": "registry.redhat.io",
                    "repository": f"rhoai/{base_name}",
                    "release_name": version,
                    "published": True
                }],
                "sum_security_status": {
                    "critical": 0,
                    "high": 2,
                    "medium": 5,
                    "low": 8,
                    "unknown": 0
                },
                "parsed_data": {
                    "architecture": "amd64",
                    "size": 1024000000
                },
                "mock_data": True,
                "last_updated": "2024-11-15T00:00:00Z"
            },
            {
                "_id": f"mock-image-{product_id}-2",
                "architecture": "arm64", 
                "repositories": [{
                    "product_id": product_id,
                    "registry": "registry.redhat.io",
                    "repository": f"rhoai/{base_name}",
                    "release_name": version,
                    "published": True
                }],
                "sum_security_status": {
                    "critical": 1,
                    "high": 1,
                    "medium": 3,
                    "low": 6,
                    "unknown": 0
                },
                "parsed_data": {
                    "architecture": "arm64",
                    "size": 950000000
                },
                "mock_data": True,
                "last_updated": "2024-11-15T00:00:00Z"
            }
        ]
        
        logger.info(f"Generated {len(mock_images)} mock images for product {product_id}")
        return mock_images
    
    def get_image_vulnerabilities(self, image_id: str) -> List[Dict[str, Any]]:
        """Get vulnerability information for a specific image with mock data fallback."""
        # If this is mock data, return mock vulnerabilities
        if image_id.startswith("mock-"):
            return self._get_mock_vulnerabilities(image_id)
        
        endpoint = f"images/{image_id}/vulnerabilities"
        
        try:
            response = self._make_request(endpoint)
            vulnerabilities = response.get("data", [])
            logger.debug(f"Found {len(vulnerabilities)} vulnerabilities for image {image_id}")
            return vulnerabilities
        except PyxisAPIError:
            logger.warning(f"Failed to get vulnerabilities for image: {image_id}. Returning mock data.")
            return self._get_mock_vulnerabilities(image_id)
    
    def _get_mock_vulnerabilities(self, image_id: str) -> List[Dict[str, Any]]:
        """Generate mock vulnerability data for an image."""
        mock_vulnerabilities = [
            {
                "cve_id": "CVE-2024-12345",
                "severity": "High",
                "cvss_score": 7.8,
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "description": "Mock vulnerability in OpenSSL affecting cryptographic operations",
                "published_date": "2024-10-15",
                "affected_package": "openssl",
                "fixed_version": "1.1.1w-1",
                "fix_status": "fixed",
                "mock_data": True
            },
            {
                "cve_id": "CVE-2024-54321", 
                "severity": "Medium",
                "cvss_score": 5.5,
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                "description": "Mock vulnerability in curl library affecting network operations",
                "published_date": "2024-11-01",
                "affected_package": "curl",
                "fixed_version": "7.76.1-2",
                "fix_status": "fixed",
                "mock_data": True
            },
            {
                "cve_id": "CVE-2024-99999",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "description": "Mock critical vulnerability in base system component",
                "published_date": "2024-11-20",
                "affected_package": "glibc",
                "fixed_version": None,
                "fix_status": "unfixed",
                "mock_data": True
            }
        ]
        
        logger.info(f"Generated {len(mock_vulnerabilities)} mock vulnerabilities for image {image_id}")
        return mock_vulnerabilities
    
    def get_image_details(self, image_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific image."""
        endpoint = f"images/{image_id}"
        params = {
            "include": "data.repositories,data.sum_security_status,data.rpm_manifest"
        }
        
        try:
            response = self._make_request(endpoint, params)
            return response.get("data", {})
        except PyxisAPIError:
            logger.warning(f"Failed to get details for image: {image_id}")
            return None
    
    async def get_images_async(self, product_id: str, release_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Asynchronously get container images for better performance."""
        if not config.ENABLE_ASYNC_PROCESSING:
            return self.get_container_images(product_id, release_version)
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=self.headers
        ) as session:
            params = {
                "filter": f"repositories.published==true",
                "include": "data.repositories,data.sum_security_status",
                "page_size": config.BATCH_SIZE,
            }
            
            if product_id:
                if "filter" in params:
                    params["filter"] += f";repositories.product_id=={product_id}"
                else:
                    params["filter"] = f"repositories.product_id=={product_id}"
            
            if release_version:
                if "filter" in params:
                    params["filter"] += f";repositories.release_name=={release_version}"
                else:
                    params["filter"] = f"repositories.release_name=={release_version}"
            
            # First, get the total count
            url = self._build_url("images", {**params, "page": 0})
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Failed to get images: {response.status}")
                    return []
                
                data = await response.json()
                total_items = data.get("total", 0)
                first_batch = data.get("data", [])
            
            if total_items <= config.BATCH_SIZE:
                return first_batch
            
            # Calculate pages needed
            total_pages = (total_items // config.BATCH_SIZE) + 1
            max_pages = min(total_pages, config.MAX_IMAGES_PER_RELEASE // config.BATCH_SIZE)
            
            # Create tasks for remaining pages
            tasks = []
            for page in range(1, max_pages):
                task_params = {**params, "page": page}
                task_url = self._build_url("images", task_params)
                tasks.append(self._fetch_page_async(session, task_url))
            
            # Execute all tasks concurrently
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Combine results
                all_images = first_batch.copy()
                for result in results:
                    if isinstance(result, list):
                        all_images.extend(result)
                    elif isinstance(result, Exception):
                        logger.warning(f"Failed to fetch page: {result}")
                
                return all_images
            
            return first_batch
    
    async def _fetch_page_async(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Fetch a single page of results asynchronously."""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", [])
                else:
                    logger.warning(f"Failed to fetch page {url}: {response.status}")
                    return []
        except Exception as e:
            logger.warning(f"Error fetching page {url}: {e}")
            return []
    
    def health_check(self) -> bool:
        """Check if the Pyxis API is accessible."""
        try:
            # Try to get a small number of repositories instead of products
            self._make_request("repositories", {"page_size": 1})
            return True
        except PyxisAPIError:
            logger.warning("Repositories endpoint failed, trying product-listings...")
            try:
                # Fallback to product-listings endpoint
                self._make_request("product-listings", {"page_size": 1})
                return True
            except PyxisAPIError:
                logger.error("Both repositories and product-listings endpoints failed")
                return False