"""Security Data API client for Red Hat security information."""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..config import config

logger = logging.getLogger(__name__)


class SecurityDataAPIError(Exception):
    """Custom exception for Security Data API errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class SecurityDataClient:
    """Client for interacting with Red Hat Security Data API."""
    
    def __init__(self, base_url: Optional[str] = None, timeout: Optional[int] = None):
        self.base_url = base_url or config.SECURITY_DATA_BASE_URL
        self.timeout = timeout or config.REQUEST_TIMEOUT
        self.headers = config.get_security_data_headers()
        
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
    
    def _build_url(self, endpoint: str) -> str:
        """Build full URL for the endpoint."""
        return urljoin(self.base_url, endpoint)
    
    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """Make HTTP request to Security Data API."""
        url = self._build_url(endpoint)
        
        try:
            logger.debug(f"Making request to: {url}")
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            logger.debug(f"Received security data response")
            return data
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error {e.response.status_code} for {url}"
            try:
                error_data = e.response.json()
                error_msg += f": {error_data.get('message', 'Unknown error')}"
            except ValueError:
                error_msg += f": {e.response.text}"
            
            logger.error(error_msg)
            raise SecurityDataAPIError(error_msg, e.response.status_code, getattr(e.response, 'json', lambda: None)())
        
        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed for {url}: {str(e)}"
            logger.error(error_msg)
            raise SecurityDataAPIError(error_msg)
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific CVE."""
        if not cve_id.startswith("CVE-"):
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return None
        
        endpoint = f"cve/{cve_id}.json"
        
        try:
            data = self._make_request(endpoint)
            logger.debug(f"Retrieved details for CVE: {cve_id}")
            return data
        except SecurityDataAPIError as e:
            if e.status_code == 404:
                logger.warning(f"CVE not found: {cve_id}")
            else:
                logger.error(f"Failed to get CVE details for {cve_id}: {e}")
            return None
    
    def get_multiple_cve_details(self, cve_ids: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Get details for multiple CVEs."""
        results = {}
        
        for cve_id in cve_ids:
            results[cve_id] = self.get_cve_details(cve_id)
        
        return results
    
    def get_errata_details(self, advisory_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific errata/advisory."""
        if not advisory_id:
            logger.warning("Empty advisory ID provided")
            return None
        
        endpoint = f"errata/{advisory_id}.json"
        
        try:
            data = self._make_request(endpoint)
            logger.debug(f"Retrieved details for advisory: {advisory_id}")
            return data
        except SecurityDataAPIError as e:
            if e.status_code == 404:
                logger.warning(f"Advisory not found: {advisory_id}")
            else:
                logger.error(f"Failed to get advisory details for {advisory_id}: {e}")
            return None
    
    def search_cves_by_severity(self, severity: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for CVEs by severity level."""
        # Note: This endpoint may not be available in the public API
        # This is a placeholder for potential future functionality
        logger.warning("CVE search by severity not implemented in public API")
        return []
    
    def get_cve_metrics(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Extract CVSS and other metrics from CVE data."""
        cve_data = self.get_cve_details(cve_id)
        if not cve_data:
            return None
        
        metrics = {
            "cve_id": cve_id,
            "cvss_score": None,
            "cvss_vector": None,
            "severity": None,
            "published_date": None,
            "modified_date": None,
            "description": None,
        }
        
        try:
            # Extract CVSS information
            if "cvss" in cve_data:
                cvss_data = cve_data["cvss"]
                if isinstance(cvss_data, dict):
                    metrics["cvss_score"] = cvss_data.get("cvss_base_score")
                    metrics["cvss_vector"] = cvss_data.get("cvss_scoring_vector")
            
            # Extract severity
            if "threat_severity" in cve_data:
                metrics["severity"] = cve_data["threat_severity"]
            
            # Extract dates
            if "public_date" in cve_data:
                metrics["published_date"] = cve_data["public_date"]
            
            if "last_modified_date" in cve_data:
                metrics["modified_date"] = cve_data["last_modified_date"]
            
            # Extract description
            if "details" in cve_data:
                details = cve_data["details"]
                if isinstance(details, list) and details:
                    metrics["description"] = details[0]
                elif isinstance(details, str):
                    metrics["description"] = details
            
            # Fallback for description
            if not metrics["description"] and "bugzilla_description" in cve_data:
                metrics["description"] = cve_data["bugzilla_description"]
            
            logger.debug(f"Extracted metrics for {cve_id}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error extracting metrics for {cve_id}: {e}")
            return metrics
    
    def get_errata_cves(self, advisory_id: str) -> List[str]:
        """Get list of CVEs associated with an errata/advisory."""
        errata_data = self.get_errata_details(advisory_id)
        if not errata_data:
            return []
        
        cve_list = []
        try:
            # Extract CVEs from errata data
            if "cves" in errata_data:
                cves = errata_data["cves"]
                if isinstance(cves, list):
                    cve_list = cves
                elif isinstance(cves, str):
                    # Sometimes CVEs are in a single string, comma-separated
                    cve_list = [cve.strip() for cve in cves.split(",") if cve.strip()]
            
            # Also check for CVEs in description or summary
            for field in ["description", "summary", "synopsis"]:
                if field in errata_data and errata_data[field]:
                    text = errata_data[field]
                    # Simple regex to find CVE patterns
                    import re
                    found_cves = re.findall(r'CVE-\d{4}-\d+', text)
                    cve_list.extend(found_cves)
            
            # Remove duplicates and sort
            cve_list = sorted(list(set(cve_list)))
            logger.debug(f"Found {len(cve_list)} CVEs for advisory {advisory_id}")
            
        except Exception as e:
            logger.error(f"Error extracting CVEs from advisory {advisory_id}: {e}")
        
        return cve_list
    
    async def get_multiple_cve_details_async(self, cve_ids: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Asynchronously get details for multiple CVEs for better performance."""
        if not config.ENABLE_ASYNC_PROCESSING or len(cve_ids) <= 5:
            return self.get_multiple_cve_details(cve_ids)
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=self.headers
        ) as session:
            
            # Create tasks for all CVEs
            tasks = []
            for cve_id in cve_ids:
                if cve_id.startswith("CVE-"):
                    url = self._build_url(f"cve/{cve_id}.json")
                    tasks.append(self._fetch_cve_async(session, cve_id, url))
            
            # Execute tasks with concurrency limit
            semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_REQUESTS)
            limited_tasks = [self._limited_fetch(semaphore, task) for task in tasks]
            
            results = await asyncio.gather(*limited_tasks, return_exceptions=True)
            
            # Process results
            cve_details = {}
            for result in results:
                if isinstance(result, tuple) and len(result) == 2:
                    cve_id, data = result
                    cve_details[cve_id] = data
                elif isinstance(result, Exception):
                    logger.warning(f"Failed to fetch CVE: {result}")
            
            return cve_details
    
    async def _limited_fetch(self, semaphore: asyncio.Semaphore, coro):
        """Limit concurrent requests using semaphore."""
        async with semaphore:
            return await coro
    
    async def _fetch_cve_async(self, session: aiohttp.ClientSession, cve_id: str, url: str) -> tuple:
        """Fetch a single CVE asynchronously."""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return (cve_id, data)
                elif response.status == 404:
                    logger.debug(f"CVE not found: {cve_id}")
                    return (cve_id, None)
                else:
                    logger.warning(f"Failed to fetch CVE {cve_id}: {response.status}")
                    return (cve_id, None)
        except Exception as e:
            logger.warning(f"Error fetching CVE {cve_id}: {e}")
            return (cve_id, None)
    
    def extract_package_vulnerabilities(self, cve_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract package vulnerability information from CVE data."""
        packages = []
        
        try:
            # Look for affected packages in various fields
            if "affected_packages" in cve_data:
                affected = cve_data["affected_packages"]
                if isinstance(affected, list):
                    for pkg in affected:
                        if isinstance(pkg, dict):
                            packages.append({
                                "package_name": pkg.get("package_name", ""),
                                "fixed_version": pkg.get("fixed_version", ""),
                                "cpe": pkg.get("cpe", ""),
                            })
            
            # Fallback: check for package information in other fields
            if not packages and "package_state" in cve_data:
                package_state = cve_data["package_state"]
                if isinstance(package_state, list):
                    for state in package_state:
                        if isinstance(state, dict):
                            packages.append({
                                "package_name": state.get("package_name", ""),
                                "fixed_version": state.get("fix_state", ""),
                                "cpe": state.get("cpe", ""),
                            })
            
        except Exception as e:
            logger.error(f"Error extracting package vulnerabilities: {e}")
        
        return packages
    
    def health_check(self) -> bool:
        """Check if the Security Data API is accessible."""
        try:
            # Try to get a well-known CVE
            test_cve = "CVE-2021-44228"  # Log4j vulnerability
            result = self.get_cve_details(test_cve)
            return result is not None
        except SecurityDataAPIError:
            return False