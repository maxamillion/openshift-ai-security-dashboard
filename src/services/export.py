"""Export service for OpenShift AI Security Dashboard."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import csv
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from .cve_analyzer import CVEAnalyzer, SecurityMetrics, ImageSecurityInfo, CVEInfo
from ..database.connection import get_db_session
from ..database.models import Release
from ..config import config

logger = logging.getLogger(__name__)


class ExportService:
    """Service for exporting security data in various formats."""
    
    def __init__(self):
        self.analyzer = CVEAnalyzer()
        self.export_dir = config.EXPORT_DIR
        self.export_dir.mkdir(parents=True, exist_ok=True)
    
    def export_release_data(self, release_id: int, format: str, scope: str = "full") -> str:
        """Export release data in specified format.
        
        Args:
            release_id: ID of the release to export
            format: Export format (pdf, csv, json)
            scope: Export scope (full, filtered, summary)
            
        Returns:
            Path to the exported file
        """
        if format not in config.ALLOWED_EXPORT_FORMATS:
            raise ValueError(f"Unsupported export format: {format}")
        
        # Get release information
        with get_db_session() as session:
            release = session.query(Release).filter_by(id=release_id).first()
            if not release:
                raise ValueError(f"Release not found: {release_id}")
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"openshift_ai_security_{release.version}_{scope}_{timestamp}.{format}"
        filepath = self.export_dir / filename
        
        try:
            if format == "json":
                self._export_json(release_id, filepath, scope)
            elif format == "csv":
                self._export_csv(release_id, filepath, scope)
            elif format == "pdf":
                self._export_pdf(release_id, filepath, scope)
            
            logger.info(f"Export completed: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            raise
    
    def _export_json(self, release_id: int, filepath: Path, scope: str):
        """Export data as JSON."""
        # Get comprehensive data
        metrics = self.analyzer.get_release_security_metrics(release_id)
        images = self.analyzer.get_image_security_info(release_id)
        
        if scope == "summary":
            cves, total_count = self.analyzer.get_cve_details(release_id, limit=50)
        else:
            cves, total_count = self.analyzer.get_cve_details(release_id)
        
        # Get release information
        with get_db_session() as session:
            release = session.query(Release).filter_by(id=release_id).first()
        
        data = {
            "export_metadata": {
                "format": "json",
                "scope": scope,
                "generated_at": datetime.utcnow().isoformat(),
                "generator": f"{config.APP_NAME} v{config.VERSION}"
            },
            "release": {
                "id": release.id,
                "version": release.version,
                "release_date": release.release_date.isoformat() if release.release_date else None,
                "support_status": release.support_status
            },
            "security_metrics": {
                "total_images": metrics.total_images,
                "total_cves": metrics.total_cves,
                "unique_cves": metrics.unique_cves,
                "severity_distribution": metrics.severity_distribution,
                "fix_status_distribution": metrics.fix_status_distribution,
                "risk_score": round(metrics.risk_score, 2)
            },
            "container_images": [
                {
                    "image_name": img.image_name,
                    "image_tag": img.image_tag,
                    "display_name": img.display_name,
                    "total_cves": img.total_cves,
                    "critical_cves": img.critical_cves,
                    "high_cves": img.high_cves,
                    "medium_cves": img.medium_cves,
                    "low_cves": img.low_cves,
                    "risk_level": img.risk_level,
                    "registry_path": img.registry_path,
                    "size_bytes": img.size_bytes,
                    "last_updated": img.last_updated.isoformat() if img.last_updated else None
                }
                for img in images
            ],
            "vulnerabilities": [
                {
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "description": cve.description,
                    "published_date": cve.published_date.isoformat() if cve.published_date else None,
                    "modified_date": cve.modified_date.isoformat() if cve.modified_date else None,
                    "affected_images_count": cve.affected_images_count,
                    "affected_packages": cve.affected_packages,
                    "fix_status": cve.fix_status,
                    "url": f"https://access.redhat.com/security/cve/{cve.cve_id}"
                }
                for cve in cves
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    def _export_csv(self, release_id: int, filepath: Path, scope: str):
        """Export data as CSV (multiple sheets in ZIP)."""
        import zipfile
        
        # Create a ZIP file with multiple CSV files
        zip_filepath = filepath.with_suffix('.zip')
        
        with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Export images CSV
            images = self.analyzer.get_image_security_info(release_id)
            images_csv = self._create_images_csv(images)
            zipf.writestr("container_images.csv", images_csv)
            
            # Export CVEs CSV
            if scope == "summary":
                cves, _ = self.analyzer.get_cve_details(release_id, limit=100)
            else:
                cves, _ = self.analyzer.get_cve_details(release_id)
            
            cves_csv = self._create_cves_csv(cves)
            zipf.writestr("vulnerabilities.csv", cves_csv)
            
            # Export summary CSV
            metrics = self.analyzer.get_release_security_metrics(release_id)
            summary_csv = self._create_summary_csv(release_id, metrics)
            zipf.writestr("security_summary.csv", summary_csv)
        
        # Remove the original filepath and rename zip
        filepath.unlink(missing_ok=True)
        zip_filepath.rename(filepath.with_suffix('.zip'))
    
    def _create_images_csv(self, images: List[ImageSecurityInfo]) -> str:
        """Create CSV content for container images."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "Image Name",
            "Image Tag",
            "Total CVEs",
            "Critical CVEs",
            "High CVEs",
            "Medium CVEs",
            "Low CVEs",
            "Risk Level",
            "Registry Path",
            "Size (Bytes)",
            "Last Updated"
        ])
        
        # Data rows
        for img in images:
            writer.writerow([
                img.image_name,
                img.image_tag or "",
                img.total_cves,
                img.critical_cves,
                img.high_cves,
                img.medium_cves,
                img.low_cves,
                img.risk_level,
                img.registry_path or "",
                img.size_bytes or "",
                img.last_updated.isoformat() if img.last_updated else ""
            ])
        
        return output.getvalue()
    
    def _create_cves_csv(self, cves: List[CVEInfo]) -> str:
        """Create CSV content for CVEs."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "CVE ID",
            "Severity",
            "CVSS Score",
            "Description",
            "Published Date",
            "Modified Date",
            "Affected Images Count",
            "Affected Packages",
            "Fix Status",
            "URL"
        ])
        
        # Data rows
        for cve in cves:
            writer.writerow([
                cve.cve_id,
                cve.severity or "",
                cve.cvss_score or "",
                (cve.description or "")[:500],  # Truncate long descriptions
                cve.published_date.isoformat() if cve.published_date else "",
                cve.modified_date.isoformat() if cve.modified_date else "",
                cve.affected_images_count,
                "; ".join(cve.affected_packages),
                cve.fix_status or "",
                f"https://access.redhat.com/security/cve/{cve.cve_id}"
            ])
        
        return output.getvalue()
    
    def _create_summary_csv(self, release_id: int, metrics: SecurityMetrics) -> str:
        """Create CSV content for security summary."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Get release info
        with get_db_session() as session:
            release = session.query(Release).filter_by(id=release_id).first()
        
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Release Version", release.version])
        writer.writerow(["Export Date", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["", ""])  # Empty row
        
        writer.writerow(["Security Metrics", ""])
        writer.writerow(["Total Images", metrics.total_images])
        writer.writerow(["Total CVEs", metrics.total_cves])
        writer.writerow(["Unique CVEs", metrics.unique_cves])
        writer.writerow(["Critical CVEs", metrics.critical_cves])
        writer.writerow(["High CVEs", metrics.high_cves])
        writer.writerow(["Medium CVEs", metrics.medium_cves])
        writer.writerow(["Low CVEs", metrics.low_cves])
        writer.writerow(["Unknown Severity CVEs", metrics.unknown_severity_cves])
        writer.writerow(["Fixed CVEs", metrics.fixed_cves])
        writer.writerow(["Unfixed CVEs", metrics.unfixed_cves])
        writer.writerow(["Risk Score", f"{metrics.risk_score:.2f}"])
        
        return output.getvalue()
    
    def _export_pdf(self, release_id: int, filepath: Path, scope: str):
        """Export data as PDF report."""
        # Get data
        metrics = self.analyzer.get_release_security_metrics(release_id)
        images = self.analyzer.get_image_security_info(release_id)
        
        if scope == "summary":
            cves, _ = self.analyzer.get_cve_details(release_id, limit=20)
            top_images = images[:10]
        else:
            cves, _ = self.analyzer.get_cve_details(release_id, limit=50)
            top_images = images[:20]
        
        # Get release info
        with get_db_session() as session:
            release = session.query(Release).filter_by(id=release_id).first()
        
        # Create PDF document
        doc = SimpleDocTemplate(str(filepath), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph(f"OpenShift AI Security Report", title_style))
        story.append(Paragraph(f"Release: {release.version}", styles['Heading2']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_data = [
            ["Metric", "Value"],
            ["Total Container Images", str(metrics.total_images)],
            ["Total CVEs", str(metrics.total_cves)],
            ["Unique CVEs", str(metrics.unique_cves)],
            ["Critical CVEs", str(metrics.critical_cves)],
            ["High CVEs", str(metrics.high_cves)],
            ["Medium CVEs", str(metrics.medium_cves)],
            ["Low CVEs", str(metrics.low_cves)],
            ["Overall Risk Score", f"{metrics.risk_score:.2f}/100"]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Top Vulnerable Images
        story.append(Paragraph("Most Vulnerable Container Images", styles['Heading2']))
        if top_images:
            images_data = [["Image Name", "Tag", "Total CVEs", "Critical", "High", "Risk Level"]]
            for img in top_images:
                images_data.append([
                    img.image_name[:40] + "..." if len(img.image_name) > 40 else img.image_name,
                    img.image_tag or "latest",
                    str(img.total_cves),
                    str(img.critical_cves),
                    str(img.high_cves),
                    img.risk_level
                ])
            
            images_table = Table(images_data, colWidths=[2.2*inch, 0.8*inch, 0.6*inch, 0.6*inch, 0.6*inch, 0.8*inch])
            images_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(images_table)
        else:
            story.append(Paragraph("No vulnerable images found.", styles['Normal']))
        
        story.append(Spacer(1, 20))
        
        # Critical CVEs
        critical_cves = [cve for cve in cves if cve.severity == "Critical"]
        if critical_cves:
            story.append(Paragraph("Critical Vulnerabilities", styles['Heading2']))
            cves_data = [["CVE ID", "CVSS Score", "Affected Images", "Fix Status"]]
            for cve in critical_cves[:10]:  # Limit to top 10
                cves_data.append([
                    cve.cve_id,
                    str(cve.cvss_score) if cve.cvss_score else "N/A",
                    str(cve.affected_images_count),
                    cve.fix_status or "Unknown"
                ])
            
            cves_table = Table(cves_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1*inch])
            cves_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(cves_table)
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            f"Report generated by {config.APP_NAME} v{config.VERSION}", 
            styles['Normal']
        ))
        
        # Build PDF
        doc.build(story)
    
    def get_export_size_estimate(self, release_id: int, format: str) -> Dict[str, Any]:
        """Estimate the size of an export file."""
        metrics = self.analyzer.get_release_security_metrics(release_id)
        
        # Rough size estimates based on format and data volume
        base_sizes = {
            "json": 1024,  # Base overhead in bytes
            "csv": 2048,   # ZIP overhead
            "pdf": 10240   # PDF overhead
        }
        
        # Per-record estimates
        per_image_size = {
            "json": 200,
            "csv": 150,
            "pdf": 50
        }
        
        per_cve_size = {
            "json": 300,
            "csv": 200,
            "pdf": 30
        }
        
        estimated_size = (
            base_sizes.get(format, 1024) +
            (metrics.total_images * per_image_size.get(format, 100)) +
            (metrics.unique_cves * per_cve_size.get(format, 150))
        )
        
        # Convert to MB and add 20% buffer
        estimated_mb = (estimated_size * 1.2) / (1024 * 1024)
        
        return {
            "estimated_size_bytes": int(estimated_size * 1.2),
            "estimated_size_mb": round(estimated_mb, 2),
            "within_limits": estimated_mb <= config.MAX_EXPORT_SIZE_MB,
            "max_allowed_mb": config.MAX_EXPORT_SIZE_MB
        }
    
    def list_exports(self) -> List[Dict[str, Any]]:
        """List available export files."""
        exports = []
        
        for file_path in self.export_dir.glob("openshift_ai_security_*"):
            if file_path.is_file():
                stat = file_path.stat()
                exports.append({
                    "filename": file_path.name,
                    "filepath": str(file_path),
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created_at": datetime.fromtimestamp(stat.st_ctime),
                    "modified_at": datetime.fromtimestamp(stat.st_mtime)
                })
        
        # Sort by creation time, newest first
        exports.sort(key=lambda x: x["created_at"], reverse=True)
        return exports
    
    def cleanup_old_exports(self, days: int = 7) -> int:
        """Clean up export files older than specified days."""
        cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
        cleaned_count = 0
        
        for file_path in self.export_dir.glob("openshift_ai_security_*"):
            if file_path.is_file() and file_path.stat().st_ctime < cutoff_time:
                try:
                    file_path.unlink()
                    cleaned_count += 1
                    logger.info(f"Deleted old export: {file_path.name}")
                except Exception as e:
                    logger.warning(f"Failed to delete {file_path.name}: {e}")
        
        return cleaned_count