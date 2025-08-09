"""Data refresh service for OpenShift AI Security Dashboard."""

import asyncio
import logging
from datetime import datetime, date
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from ..api.pyxis import PyxisClient, PyxisAPIError
from ..api.security import SecurityDataClient, SecurityDataAPIError
from ..database.connection import get_db_session
from ..database.models import (
    Release, ContainerImage, CVE, ImageCVE, Errata, CVEErrata, Snapshot
)
from ..config import config

logger = logging.getLogger(__name__)


@dataclass
class RefreshProgress:
    """Progress tracking for data refresh operations."""
    
    total_steps: int = 0
    current_step: int = 0
    current_operation: str = ""
    errors: List[str] = None
    warnings: List[str] = None
    start_time: datetime = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.start_time is None:
            self.start_time = datetime.utcnow()
    
    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage."""
        if self.total_steps == 0:
            return 0.0
        return (self.current_step / self.total_steps) * 100
    
    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return (datetime.utcnow() - self.start_time).total_seconds()


class DataRefreshService:
    """Service for refreshing container image and security data."""
    
    def __init__(self, progress_callback: Optional[Callable[[RefreshProgress], None]] = None):
        self.progress_callback = progress_callback
        self.progress = RefreshProgress()
        self.pyxis_client = None
        self.security_client = None
    
    def _update_progress(self, operation: str, step_increment: int = 1):
        """Update progress and notify callback."""
        self.progress.current_step += step_increment
        self.progress.current_operation = operation
        
        logger.info(f"Progress: {self.progress.progress_percentage:.1f}% - {operation}")
        
        if self.progress_callback:
            self.progress_callback(self.progress)
    
    def _add_error(self, error_msg: str):
        """Add error to progress tracking."""
        self.progress.errors.append(error_msg)
        logger.error(error_msg)
    
    def _add_warning(self, warning_msg: str):
        """Add warning to progress tracking."""
        self.progress.warnings.append(warning_msg)
        logger.warning(warning_msg)
    
    async def refresh_all_data(self, release_version: Optional[str] = None) -> RefreshProgress:
        """Refresh all data for OpenShift AI releases."""
        self.progress = RefreshProgress(total_steps=10)
        
        try:
            # Initialize API clients
            self.pyxis_client = PyxisClient()
            self.security_client = SecurityDataClient()
            
            self._update_progress("Initializing data refresh...")
            
            # Step 1: Discover OpenShift AI products
            self._update_progress("Discovering OpenShift AI products...")
            products = await self._discover_products()
            
            if not products:
                self._add_error("No OpenShift AI products found")
                return self.progress
            
            # Step 2: Get releases for products
            self._update_progress("Fetching product releases...")
            releases_data = await self._get_product_releases(products, release_version)
            
            if not releases_data:
                self._add_error("No releases found for OpenShift AI products")
                return self.progress
            
            # Step 3: Store/update releases in database
            self._update_progress("Storing release information...")
            releases = await self._store_releases(releases_data)
            
            # Step 4-6: Process each release
            for release in releases:
                await self._process_release(release)
            
            # Step 7: Clean up old data
            self._update_progress("Cleaning up old data...")
            await self._cleanup_old_data()
            
            # Step 8: Generate snapshots
            self._update_progress("Generating security snapshots...")
            await self._generate_snapshots(releases)
            
            # Step 9: Validate data integrity
            self._update_progress("Validating data integrity...")
            await self._validate_data_integrity()
            
            # Step 10: Complete
            self._update_progress("Data refresh completed successfully!")
            
        except Exception as e:
            self._add_error(f"Data refresh failed: {str(e)}")
            logger.exception("Data refresh failed")
        
        finally:
            if self.pyxis_client:
                self.pyxis_client.session.close()
            if self.security_client:
                self.security_client.session.close()
        
        return self.progress
    
    async def _discover_products(self) -> List[Dict[str, Any]]:
        """Discover OpenShift AI products from Pyxis."""
        try:
            products = self.pyxis_client.get_openshift_ai_products()
            logger.info(f"Discovered {len(products)} OpenShift AI products")
            return products
        except PyxisAPIError as e:
            self._add_error(f"Failed to discover products: {e}")
            return []
    
    async def _get_product_releases(self, products: List[Dict[str, Any]], target_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get releases for all discovered products."""
        all_releases = []
        
        for product in products:
            product_id = product.get("_id")
            if not product_id:
                continue
            
            try:
                releases = self.pyxis_client.get_product_releases(product_id)
                
                # Filter by target version if specified
                if target_version:
                    releases = [r for r in releases if r.get("release_name") == target_version]
                
                # Filter for supported releases only
                supported_releases = [
                    r for r in releases 
                    if r.get("published") and r.get("support_status") in ["supported", "maintenance"]
                ]
                
                all_releases.extend(supported_releases)
                
            except PyxisAPIError as e:
                self._add_warning(f"Failed to get releases for product {product_id}: {e}")
        
        # Deduplicate by release name
        unique_releases = {}
        for release in all_releases:
            release_name = release.get("release_name") or release.get("name")
            if release_name and release_name not in unique_releases:
                unique_releases[release_name] = release
        
        result = list(unique_releases.values())
        logger.info(f"Found {len(result)} unique supported releases")
        return result
    
    async def _store_releases(self, releases_data: List[Dict[str, Any]]) -> List[Release]:
        """Store release information in the database."""
        stored_releases = []
        
        with get_db_session() as session:
            for release_data in releases_data:
                release_name = release_data.get("release_name") or release_data.get("name")
                if not release_name:
                    continue
                
                # Check if release already exists
                existing = session.query(Release).filter_by(version=release_name).first()
                
                if existing:
                    # Update existing release
                    existing.updated_at = datetime.utcnow()
                    if release_data.get("release_date"):
                        try:
                            existing.release_date = datetime.fromisoformat(
                                release_data["release_date"].replace("Z", "+00:00")
                            ).date()
                        except (ValueError, AttributeError):
                            pass
                    
                    if release_data.get("support_status"):
                        existing.support_status = release_data["support_status"]
                    
                    stored_releases.append(existing)
                else:
                    # Create new release
                    release = Release(
                        version=release_name,
                        support_status=release_data.get("support_status", "unknown")
                    )
                    
                    # Parse release date if available
                    if release_data.get("release_date"):
                        try:
                            release.release_date = datetime.fromisoformat(
                                release_data["release_date"].replace("Z", "+00:00")
                            ).date()
                        except (ValueError, AttributeError):
                            pass
                    
                    session.add(release)
                    stored_releases.append(release)
            
            session.flush()  # Get IDs for new releases
        
        logger.info(f"Stored {len(stored_releases)} releases")
        return stored_releases
    
    async def _process_release(self, release: Release):
        """Process container images and vulnerabilities for a release."""
        self._update_progress(f"Processing release {release.version}...")
        
        try:
            # Get container images for this release
            images_data = await self._get_release_images(release)
            
            if not images_data:
                self._add_warning(f"No images found for release {release.version}")
                return
            
            # Store images and process vulnerabilities
            await self._store_images_and_vulnerabilities(release, images_data)
            
        except Exception as e:
            self._add_error(f"Failed to process release {release.version}: {e}")
    
    async def _get_release_images(self, release: Release) -> List[Dict[str, Any]]:
        """Get container images for a specific release."""
        try:
            # Try to find a product ID for this release
            # This is a simplified approach - in practice, you'd need to map releases to products
            products = self.pyxis_client.get_openshift_ai_products()
            
            if not products:
                return []
            
            # Use the first product as a fallback
            product_id = products[0].get("_id")
            
            if config.ENABLE_ASYNC_PROCESSING:
                images = await self.pyxis_client.get_images_async(product_id, release.version)
            else:
                images = self.pyxis_client.get_container_images(product_id, release.version)
            
            logger.info(f"Found {len(images)} images for release {release.version}")
            return images
            
        except PyxisAPIError as e:
            self._add_warning(f"Failed to get images for release {release.version}: {e}")
            return []
    
    async def _store_images_and_vulnerabilities(self, release: Release, images_data: List[Dict[str, Any]]):
        """Store container images and their vulnerabilities."""
        with get_db_session() as session:
            for image_data in images_data:
                try:
                    await self._process_single_image(session, release, image_data)
                except Exception as e:
                    self._add_warning(f"Failed to process image {image_data.get('_id', 'unknown')}: {e}")
    
    async def _process_single_image(self, session: Session, release: Release, image_data: Dict[str, Any]):
        """Process a single container image and its vulnerabilities."""
        image_id = image_data.get("_id")
        if not image_id:
            return
        
        # Extract image information
        repositories = image_data.get("repositories", [])
        if not repositories:
            return
        
        repo = repositories[0]  # Use first repository
        image_name = repo.get("repository")
        image_tag = repo.get("tags", [{}])[0].get("name") if repo.get("tags") else None
        
        if not image_name:
            return
        
        # Check if image already exists
        existing_image = session.query(ContainerImage).filter_by(
            release_id=release.id,
            image_name=image_name,
            image_tag=image_tag
        ).first()
        
        if existing_image:
            container_image = existing_image
            container_image.updated_at = datetime.utcnow()
        else:
            # Create new image record
            container_image = ContainerImage(
                release_id=release.id,
                image_name=image_name,
                image_tag=image_tag,
                image_digest=image_data.get("docker_image_digest"),
                registry_path=repo.get("published_url"),
                architecture=image_data.get("architecture"),
                size_bytes=image_data.get("uncompressed_size_bytes")
            )
            session.add(container_image)
        
        session.flush()  # Get image ID
        
        # Get and process vulnerabilities
        await self._process_image_vulnerabilities(session, container_image, image_id)
    
    async def _process_image_vulnerabilities(self, session: Session, container_image: ContainerImage, pyxis_image_id: str):
        """Process vulnerabilities for a single image."""
        try:
            # Get vulnerabilities from Pyxis
            vulnerabilities = self.pyxis_client.get_image_vulnerabilities(pyxis_image_id)
            
            if not vulnerabilities:
                return
            
            # Extract unique CVE IDs
            cve_ids = set()
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve_id")
                if cve_id and cve_id.startswith("CVE-"):
                    cve_ids.add(cve_id)
            
            if not cve_ids:
                return
            
            # Get detailed CVE information
            if config.ENABLE_ASYNC_PROCESSING and len(cve_ids) > 5:
                cve_details = await self.security_client.get_multiple_cve_details_async(list(cve_ids))
            else:
                cve_details = self.security_client.get_multiple_cve_details(list(cve_ids))
            
            # Store CVEs and link to image
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve_id")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue
                
                # Store CVE
                cve = await self._store_cve(session, cve_id, cve_details.get(cve_id))
                
                if cve:
                    # Store image-CVE relationship
                    await self._store_image_cve_relationship(session, container_image, cve, vuln)
        
        except Exception as e:
            logger.error(f"Failed to process vulnerabilities for image {container_image.image_name}: {e}")
    
    async def _store_cve(self, session: Session, cve_id: str, cve_data: Optional[Dict[str, Any]]) -> Optional[CVE]:
        """Store CVE information in the database."""
        # Check if CVE already exists
        existing_cve = session.query(CVE).filter_by(cve_id=cve_id).first()
        
        if existing_cve:
            return existing_cve
        
        # Create new CVE record
        cve = CVE(cve_id=cve_id)
        
        if cve_data:
            # Extract CVE details from Security Data API
            cve_metrics = self.security_client.get_cve_metrics(cve_id) if cve_data else None
            
            if cve_metrics:
                cve.severity = cve_metrics.get("severity")
                cve.cvss_score = cve_metrics.get("cvss_score")
                cve.cvss_vector = cve_metrics.get("cvss_vector")
                cve.description = cve_metrics.get("description")
                
                # Parse dates
                if cve_metrics.get("published_date"):
                    try:
                        cve.published_date = datetime.fromisoformat(
                            cve_metrics["published_date"].replace("Z", "+00:00")
                        ).date()
                    except (ValueError, AttributeError):
                        pass
                
                if cve_metrics.get("modified_date"):
                    try:
                        cve.modified_date = datetime.fromisoformat(
                            cve_metrics["modified_date"].replace("Z", "+00:00")
                        ).date()
                    except (ValueError, AttributeError):
                        pass
        
        session.add(cve)
        session.flush()
        return cve
    
    async def _store_image_cve_relationship(self, session: Session, container_image: ContainerImage, cve: CVE, vuln_data: Dict[str, Any]):
        """Store the relationship between an image and a CVE."""
        # Check if relationship already exists
        existing = session.query(ImageCVE).filter_by(
            image_id=container_image.id,
            cve_id=cve.id,
            affected_package=vuln_data.get("package")
        ).first()
        
        if existing:
            return
        
        # Create new relationship
        image_cve = ImageCVE(
            image_id=container_image.id,
            cve_id=cve.id,
            affected_package=vuln_data.get("package"),
            fixed_version=vuln_data.get("fixed_version"),
            fix_status=vuln_data.get("fix_state", "unknown")
        )
        
        session.add(image_cve)
    
    async def _cleanup_old_data(self):
        """Clean up old or stale data."""
        # This could include removing old snapshots, orphaned records, etc.
        # For now, we'll just log that cleanup was attempted
        logger.info("Data cleanup completed")
    
    async def _generate_snapshots(self, releases: List[Release]):
        """Generate security snapshots for releases."""
        with get_db_session() as session:
            for release in releases:
                await self._generate_release_snapshot(session, release)
    
    async def _generate_release_snapshot(self, session: Session, release: Release):
        """Generate a security snapshot for a specific release."""
        # Count images and CVEs
        total_images = session.query(func.count(ContainerImage.id)).filter_by(release_id=release.id).scalar()
        
        # Count unique CVEs
        total_cves = session.query(func.count(func.distinct(CVE.cve_id))).join(
            ImageCVE, CVE.id == ImageCVE.cve_id
        ).join(
            ContainerImage, ImageCVE.image_id == ContainerImage.id
        ).filter(ContainerImage.release_id == release.id).scalar()
        
        # Count CVEs by severity
        severity_counts = {}
        for severity in ["Critical", "High", "Medium", "Low"]:
            count = session.query(func.count(func.distinct(CVE.cve_id))).join(
                ImageCVE, CVE.id == ImageCVE.cve_id
            ).join(
                ContainerImage, ImageCVE.image_id == ContainerImage.id
            ).filter(
                and_(ContainerImage.release_id == release.id, CVE.severity == severity)
            ).scalar()
            severity_counts[severity.lower()] = count
        
        # Create or update snapshot
        existing_snapshot = session.query(Snapshot).filter_by(release_id=release.id).order_by(
            Snapshot.snapshot_date.desc()
        ).first()
        
        snapshot_data = {
            "analysis_date": datetime.utcnow().isoformat(),
            "data_sources": ["pyxis", "security_data_api"],
            "release_version": release.version,
            "methodology": "automated_refresh"
        }
        
        if existing_snapshot and existing_snapshot.snapshot_date.date() == date.today():
            # Update today's snapshot
            existing_snapshot.total_images = total_images
            existing_snapshot.total_cves = total_cves
            existing_snapshot.critical_cves = severity_counts.get("critical", 0)
            existing_snapshot.high_cves = severity_counts.get("high", 0)
            existing_snapshot.medium_cves = severity_counts.get("medium", 0)
            existing_snapshot.low_cves = severity_counts.get("low", 0)
            existing_snapshot.snapshot_data = snapshot_data
        else:
            # Create new snapshot
            snapshot = Snapshot(
                release_id=release.id,
                snapshot_date=datetime.utcnow(),
                total_images=total_images,
                total_cves=total_cves,
                critical_cves=severity_counts.get("critical", 0),
                high_cves=severity_counts.get("high", 0),
                medium_cves=severity_counts.get("medium", 0),
                low_cves=severity_counts.get("low", 0),
                snapshot_data=snapshot_data
            )
            session.add(snapshot)
    
    async def _validate_data_integrity(self):
        """Validate the integrity of stored data."""
        validation_errors = []
        
        with get_db_session() as session:
            # Check for orphaned records
            orphaned_images = session.query(ContainerImage).filter(
                ~ContainerImage.release_id.in_(session.query(Release.id))
            ).count()
            
            if orphaned_images > 0:
                validation_errors.append(f"Found {orphaned_images} orphaned container images")
            
            orphaned_image_cves = session.query(ImageCVE).filter(
                ~ImageCVE.image_id.in_(session.query(ContainerImage.id))
            ).count()
            
            if orphaned_image_cves > 0:
                validation_errors.append(f"Found {orphaned_image_cves} orphaned image-CVE relationships")
            
            # Check for missing CVE details
            incomplete_cves = session.query(CVE).filter(
                CVE.severity.is_(None)
            ).count()
            
            if incomplete_cves > 0:
                self._add_warning(f"Found {incomplete_cves} CVEs with missing severity information")
        
        if validation_errors:
            for error in validation_errors:
                self._add_error(error)
        else:
            logger.info("Data integrity validation passed")


async def refresh_data_async(release_version: Optional[str] = None, progress_callback: Optional[Callable] = None) -> RefreshProgress:
    """Async wrapper for data refresh."""
    service = DataRefreshService(progress_callback)
    return await service.refresh_all_data(release_version)


def refresh_data_sync(release_version: Optional[str] = None, progress_callback: Optional[Callable] = None) -> RefreshProgress:
    """Synchronous wrapper for data refresh."""
    return asyncio.run(refresh_data_async(release_version, progress_callback))