"""CVE analysis service for OpenShift AI Security Dashboard."""

import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass

from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc
import pandas as pd

from ..database.connection import get_db_session
from ..database.models import Release, ContainerImage, CVE, ImageCVE, Snapshot
from ..config import config

logger = logging.getLogger(__name__)


@dataclass
class SecurityMetrics:
    """Security metrics for a release or image."""
    
    total_images: int = 0
    total_cves: int = 0
    unique_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    medium_cves: int = 0
    low_cves: int = 0
    unknown_severity_cves: int = 0
    fixed_cves: int = 0
    unfixed_cves: int = 0
    
    @property
    def severity_distribution(self) -> Dict[str, int]:
        """Get severity distribution as dictionary."""
        return {
            "Critical": self.critical_cves,
            "High": self.high_cves,
            "Medium": self.medium_cves,
            "Low": self.low_cves,
            "Unknown": self.unknown_severity_cves,
        }
    
    @property
    def fix_status_distribution(self) -> Dict[str, int]:
        """Get fix status distribution."""
        return {
            "Fixed": self.fixed_cves,
            "Unfixed": self.unfixed_cves,
            "Unknown": self.total_cves - self.fixed_cves - self.unfixed_cves,
        }
    
    @property
    def risk_score(self) -> float:
        """Calculate a risk score based on severity distribution."""
        if self.total_cves == 0:
            return 0.0
        
        # Weighted scoring: Critical=10, High=5, Medium=2, Low=1
        weighted_score = (
            self.critical_cves * 10 +
            self.high_cves * 5 +
            self.medium_cves * 2 +
            self.low_cves * 1
        )
        
        # Normalize to 0-100 scale
        max_possible_score = self.total_cves * 10
        return (weighted_score / max_possible_score) * 100 if max_possible_score > 0 else 0.0


@dataclass
class CVEInfo:
    """Detailed CVE information."""
    
    cve_id: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    affected_images_count: int = 0
    affected_packages: List[str] = None
    fix_status: Optional[str] = None
    
    def __post_init__(self):
        if self.affected_packages is None:
            self.affected_packages = []


@dataclass
class ImageSecurityInfo:
    """Security information for a container image."""
    
    image_id: int
    image_name: str
    image_tag: Optional[str] = None
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    medium_cves: int = 0
    low_cves: int = 0
    last_updated: Optional[datetime] = None
    registry_path: Optional[str] = None
    size_bytes: Optional[int] = None
    
    @property
    def display_name(self) -> str:
        """Get display name for the image."""
        if self.image_tag:
            return f"{self.image_name}:{self.image_tag}"
        return self.image_name
    
    @property
    def risk_level(self) -> str:
        """Get risk level based on CVE distribution."""
        if self.critical_cves > 0:
            return "Critical"
        elif self.high_cves > 0:
            return "High"
        elif self.medium_cves > 0:
            return "Medium"
        elif self.low_cves > 0:
            return "Low"
        else:
            return "Minimal"


class CVEAnalyzer:
    """Service for analyzing CVE data and generating security insights."""
    
    def get_release_security_metrics(self, release_id: int) -> SecurityMetrics:
        """Get comprehensive security metrics for a release."""
        with get_db_session() as session:
            release = session.query(Release).filter_by(id=release_id).first()
            if not release:
                return SecurityMetrics()
            
            # Get image count
            total_images = session.query(func.count(ContainerImage.id)).filter_by(
                release_id=release_id
            ).scalar()
            
            # Get CVE statistics
            cve_stats = session.query(
                func.count(ImageCVE.cve_id).label("total_cves"),
                func.count(func.distinct(ImageCVE.cve_id)).label("unique_cves")
            ).join(ContainerImage).filter(
                ContainerImage.release_id == release_id
            ).first()
            
            # Get severity distribution
            severity_stats = session.query(
                CVE.severity,
                func.count(func.distinct(CVE.cve_id)).label("count")
            ).join(ImageCVE).join(ContainerImage).filter(
                ContainerImage.release_id == release_id
            ).group_by(CVE.severity).all()
            
            # Get fix status distribution
            fix_stats = session.query(
                ImageCVE.fix_status,
                func.count(func.distinct(ImageCVE.cve_id)).label("count")
            ).join(ContainerImage).filter(
                ContainerImage.release_id == release_id
            ).group_by(ImageCVE.fix_status).all()
            
            # Build metrics
            metrics = SecurityMetrics(
                total_images=total_images or 0,
                total_cves=cve_stats.total_cves or 0,
                unique_cves=cve_stats.unique_cves or 0
            )
            
            # Process severity distribution
            for severity, count in severity_stats:
                if severity == "Critical":
                    metrics.critical_cves = count
                elif severity == "High":
                    metrics.high_cves = count
                elif severity == "Medium":
                    metrics.medium_cves = count
                elif severity == "Low":
                    metrics.low_cves = count
                else:
                    metrics.unknown_severity_cves += count
            
            # Process fix status distribution
            for fix_status, count in fix_stats:
                if fix_status == "fixed":
                    metrics.fixed_cves = count
                elif fix_status == "unfixed":
                    metrics.unfixed_cves = count
            
            return metrics
    
    def get_image_security_info(self, release_id: int) -> List[ImageSecurityInfo]:
        """Get security information for all images in a release."""
        with get_db_session() as session:
            # Query images with CVE counts
            query = session.query(
                ContainerImage,
                func.count(ImageCVE.cve_id).label("total_cves"),
                func.sum(func.case([(CVE.severity == "Critical", 1)], else_=0)).label("critical_cves"),
                func.sum(func.case([(CVE.severity == "High", 1)], else_=0)).label("high_cves"),
                func.sum(func.case([(CVE.severity == "Medium", 1)], else_=0)).label("medium_cves"),
                func.sum(func.case([(CVE.severity == "Low", 1)], else_=0)).label("low_cves")
            ).outerjoin(ImageCVE).outerjoin(CVE).filter(
                ContainerImage.release_id == release_id
            ).group_by(ContainerImage.id).all()
            
            results = []
            for row in query:
                image = row.ContainerImage
                results.append(ImageSecurityInfo(
                    image_id=image.id,
                    image_name=image.image_name,
                    image_tag=image.image_tag,
                    total_cves=row.total_cves or 0,
                    critical_cves=row.critical_cves or 0,
                    high_cves=row.high_cves or 0,
                    medium_cves=row.medium_cves or 0,
                    low_cves=row.low_cves or 0,
                    last_updated=image.updated_at,
                    registry_path=image.registry_path,
                    size_bytes=image.size_bytes
                ))
            
            return sorted(results, key=lambda x: (x.critical_cves, x.high_cves, x.total_cves), reverse=True)
    
    def get_cve_details(self, release_id: Optional[int] = None, severity_filter: Optional[List[str]] = None,
                       fix_status_filter: Optional[List[str]] = None, limit: int = None,
                       offset: int = 0) -> Tuple[List[CVEInfo], int]:
        """Get detailed CVE information with filtering and pagination."""
        with get_db_session() as session:
            # Base query
            query = session.query(
                CVE,
                func.count(func.distinct(ContainerImage.id)).label("affected_images_count")
            ).join(ImageCVE).join(ContainerImage)
            
            # Apply release filter
            if release_id:
                query = query.filter(ContainerImage.release_id == release_id)
            
            # Apply severity filter
            if severity_filter:
                query = query.filter(CVE.severity.in_(severity_filter))
            
            # Apply fix status filter
            if fix_status_filter:
                query = query.filter(ImageCVE.fix_status.in_(fix_status_filter))
            
            # Group and order
            query = query.group_by(CVE.id).order_by(
                desc(func.case([
                    (CVE.severity == "Critical", 4),
                    (CVE.severity == "High", 3),
                    (CVE.severity == "Medium", 2),
                    (CVE.severity == "Low", 1)
                ], else_=0)),
                desc(CVE.cvss_score),
                CVE.cve_id
            )
            
            # Get total count for pagination
            total_count = query.count()
            
            # Apply pagination
            if limit:
                query = query.limit(limit)
            if offset:
                query = query.offset(offset)
            
            results = []
            for row in query.all():
                cve = row.CVE
                
                # Get affected packages for this CVE
                packages = session.query(func.distinct(ImageCVE.affected_package)).join(
                    ContainerImage
                ).filter(
                    ImageCVE.cve_id == cve.id
                )
                
                if release_id:
                    packages = packages.filter(ContainerImage.release_id == release_id)
                
                package_list = [pkg[0] for pkg in packages.all() if pkg[0]]
                
                # Get fix status (most common status for this CVE)
                fix_status_query = session.query(
                    ImageCVE.fix_status,
                    func.count().label("count")
                ).join(ContainerImage).filter(
                    ImageCVE.cve_id == cve.id
                )
                
                if release_id:
                    fix_status_query = fix_status_query.filter(ContainerImage.release_id == release_id)
                
                fix_status_counts = fix_status_query.group_by(ImageCVE.fix_status).all()
                most_common_status = None
                if fix_status_counts:
                    most_common_status = max(fix_status_counts, key=lambda x: x.count).fix_status
                
                results.append(CVEInfo(
                    cve_id=cve.cve_id,
                    severity=cve.severity,
                    cvss_score=cve.cvss_score,
                    description=cve.description,
                    published_date=cve.published_date,
                    modified_date=cve.modified_date,
                    affected_images_count=row.affected_images_count,
                    affected_packages=package_list,
                    fix_status=most_common_status
                ))
            
            return results, total_count
    
    def get_cves_for_image(self, image_id: int) -> List[CVEInfo]:
        """Get all CVEs affecting a specific image."""
        with get_db_session() as session:
            query = session.query(
                CVE,
                ImageCVE.affected_package,
                ImageCVE.fix_status,
                ImageCVE.fixed_version
            ).join(ImageCVE).filter(
                ImageCVE.image_id == image_id
            ).order_by(
                desc(func.case([
                    (CVE.severity == "Critical", 4),
                    (CVE.severity == "High", 3),
                    (CVE.severity == "Medium", 2),
                    (CVE.severity == "Low", 1)
                ], else_=0)),
                desc(CVE.cvss_score),
                CVE.cve_id
            )
            
            results = []
            for row in query.all():
                cve = row.CVE
                results.append(CVEInfo(
                    cve_id=cve.cve_id,
                    severity=cve.severity,
                    cvss_score=cve.cvss_score,
                    description=cve.description,
                    published_date=cve.published_date,
                    modified_date=cve.modified_date,
                    affected_images_count=1,  # This specific image
                    affected_packages=[row.affected_package] if row.affected_package else [],
                    fix_status=row.fix_status
                ))
            
            return results
    
    def compare_releases(self, release_id_1: int, release_id_2: int) -> Dict[str, Any]:
        """Compare security metrics between two releases."""
        metrics_1 = self.get_release_security_metrics(release_id_1)
        metrics_2 = self.get_release_security_metrics(release_id_2)
        
        with get_db_session() as session:
            release_1 = session.query(Release).filter_by(id=release_id_1).first()
            release_2 = session.query(Release).filter_by(id=release_id_2).first()
            
            if not release_1 or not release_2:
                return {}
            
            # Calculate differences
            comparison = {
                "release_1": {
                    "version": release_1.version,
                    "metrics": metrics_1
                },
                "release_2": {
                    "version": release_2.version,
                    "metrics": metrics_2
                },
                "differences": {
                    "total_images": metrics_2.total_images - metrics_1.total_images,
                    "total_cves": metrics_2.total_cves - metrics_1.total_cves,
                    "unique_cves": metrics_2.unique_cves - metrics_1.unique_cves,
                    "critical_cves": metrics_2.critical_cves - metrics_1.critical_cves,
                    "high_cves": metrics_2.high_cves - metrics_1.high_cves,
                    "medium_cves": metrics_2.medium_cves - metrics_1.medium_cves,
                    "low_cves": metrics_2.low_cves - metrics_1.low_cves,
                    "risk_score": metrics_2.risk_score - metrics_1.risk_score
                }
            }
            
            # Find CVEs that were fixed, introduced, or persist
            cves_1 = self._get_release_cve_set(session, release_id_1)
            cves_2 = self._get_release_cve_set(session, release_id_2)
            
            comparison["cve_changes"] = {
                "fixed": list(cves_1 - cves_2),
                "introduced": list(cves_2 - cves_1),
                "persistent": list(cves_1 & cves_2)
            }
            
            return comparison
    
    def _get_release_cve_set(self, session: Session, release_id: int) -> set:
        """Get set of CVE IDs for a release."""
        cve_ids = session.query(CVE.cve_id).join(ImageCVE).join(ContainerImage).filter(
            ContainerImage.release_id == release_id
        ).distinct().all()
        
        return {cve_id[0] for cve_id in cve_ids}
    
    def get_security_trends(self, release_id: int, days: int = 30) -> Dict[str, Any]:
        """Get security trends over time for a release."""
        with get_db_session() as session:
            # Get snapshots for the specified period
            since_date = datetime.utcnow() - timedelta(days=days)
            
            snapshots = session.query(Snapshot).filter(
                and_(
                    Snapshot.release_id == release_id,
                    Snapshot.snapshot_date >= since_date
                )
            ).order_by(Snapshot.snapshot_date).all()
            
            if not snapshots:
                return {"snapshots": [], "trends": {}}
            
            # Calculate trends
            trends = {
                "total_cves": [],
                "critical_cves": [],
                "high_cves": [],
                "medium_cves": [],
                "low_cves": [],
                "dates": []
            }
            
            for snapshot in snapshots:
                trends["dates"].append(snapshot.snapshot_date.isoformat())
                trends["total_cves"].append(snapshot.total_cves or 0)
                trends["critical_cves"].append(snapshot.critical_cves or 0)
                trends["high_cves"].append(snapshot.high_cves or 0)
                trends["medium_cves"].append(snapshot.medium_cves or 0)
                trends["low_cves"].append(snapshot.low_cves or 0)
            
            # Calculate trend direction
            trend_analysis = {}
            for metric in ["total_cves", "critical_cves", "high_cves", "medium_cves", "low_cves"]:
                values = trends[metric]
                if len(values) >= 2:
                    if values[-1] > values[0]:
                        trend_analysis[metric] = "increasing"
                    elif values[-1] < values[0]:
                        trend_analysis[metric] = "decreasing"
                    else:
                        trend_analysis[metric] = "stable"
                else:
                    trend_analysis[metric] = "insufficient_data"
            
            return {
                "snapshots": [
                    {
                        "date": s.snapshot_date.isoformat(),
                        "total_cves": s.total_cves or 0,
                        "critical_cves": s.critical_cves or 0,
                        "high_cves": s.high_cves or 0,
                        "medium_cves": s.medium_cves or 0,
                        "low_cves": s.low_cves or 0
                    }
                    for s in snapshots
                ],
                "trends": trends,
                "trend_analysis": trend_analysis
            }
    
    def get_top_vulnerable_images(self, release_id: int, limit: int = 10) -> List[ImageSecurityInfo]:
        """Get the most vulnerable images in a release."""
        images = self.get_image_security_info(release_id)
        return images[:limit]
    
    def get_cve_statistics(self, release_id: Optional[int] = None) -> Dict[str, Any]:
        """Get comprehensive CVE statistics."""
        with get_db_session() as session:
            base_query = session.query(CVE).join(ImageCVE).join(ContainerImage)
            
            if release_id:
                base_query = base_query.filter(ContainerImage.release_id == release_id)
            
            # Age distribution
            now = datetime.utcnow().date()
            age_stats = {
                "less_than_30_days": 0,
                "30_to_90_days": 0,
                "90_days_to_1_year": 0,
                "more_than_1_year": 0,
                "unknown_age": 0
            }
            
            cves_with_dates = base_query.filter(CVE.published_date.isnot(None)).all()
            for cve in cves_with_dates:
                if cve.published_date:
                    age = (now - cve.published_date).days
                    if age < 30:
                        age_stats["less_than_30_days"] += 1
                    elif age < 90:
                        age_stats["30_to_90_days"] += 1
                    elif age < 365:
                        age_stats["90_days_to_1_year"] += 1
                    else:
                        age_stats["more_than_1_year"] += 1
                else:
                    age_stats["unknown_age"] += 1
            
            # CVSS score distribution
            cvss_stats = {
                "0.0_to_3.9": 0,
                "4.0_to_6.9": 0,
                "7.0_to_8.9": 0,
                "9.0_to_10.0": 0,
                "no_score": 0
            }
            
            cves_with_scores = base_query.filter(CVE.cvss_score.isnot(None)).all()
            for cve in cves_with_scores:
                if cve.cvss_score is not None:
                    score = float(cve.cvss_score)
                    if score < 4.0:
                        cvss_stats["0.0_to_3.9"] += 1
                    elif score < 7.0:
                        cvss_stats["4.0_to_6.9"] += 1
                    elif score < 9.0:
                        cvss_stats["7.0_to_8.9"] += 1
                    else:
                        cvss_stats["9.0_to_10.0"] += 1
                else:
                    cvss_stats["no_score"] += 1
            
            return {
                "age_distribution": age_stats,
                "cvss_distribution": cvss_stats,
                "total_analyzed": len(cves_with_dates) + len(cves_with_scores)
            }
    
    def export_security_data(self, release_id: int, format: str = "dict") -> Any:
        """Export security data in various formats."""
        metrics = self.get_release_security_metrics(release_id)
        images = self.get_image_security_info(release_id)
        cves, _ = self.get_cve_details(release_id)
        
        data = {
            "release_metrics": metrics,
            "images": images,
            "cves": cves,
            "export_timestamp": datetime.utcnow().isoformat()
        }
        
        if format == "pandas":
            # Convert to pandas DataFrames for analysis
            images_df = pd.DataFrame([
                {
                    "image_name": img.image_name,
                    "image_tag": img.image_tag,
                    "total_cves": img.total_cves,
                    "critical_cves": img.critical_cves,
                    "high_cves": img.high_cves,
                    "medium_cves": img.medium_cves,
                    "low_cves": img.low_cves,
                    "risk_level": img.risk_level
                }
                for img in images
            ])
            
            cves_df = pd.DataFrame([
                {
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "affected_images_count": cve.affected_images_count,
                    "fix_status": cve.fix_status,
                    "published_date": cve.published_date
                }
                for cve in cves
            ])
            
            return {
                "metrics": metrics,
                "images_df": images_df,
                "cves_df": cves_df
            }
        
        return data