"""Tests for CVE analyzer service."""

import pytest
from datetime import datetime, date
from unittest.mock import patch

from src.services.cve_analyzer import CVEAnalyzer, SecurityMetrics, CVEInfo, ImageSecurityInfo
from src.database.models import Release, ContainerImage, CVE, ImageCVE


class TestCVEAnalyzer:
    """Test cases for CVEAnalyzer."""
    
    def test_get_release_security_metrics(self, db_session, sample_release, sample_container_image, sample_cve, sample_image_cve):
        """Test getting security metrics for a release."""
        analyzer = CVEAnalyzer()
        
        # Add another CVE for more comprehensive testing
        cve2 = CVE(
            cve_id="CVE-2024-54321",
            severity="Critical",
            cvss_score=9.8
        )
        db_session.add(cve2)
        db_session.flush()
        
        image_cve2 = ImageCVE(
            image_id=sample_container_image.id,
            cve_id=cve2.id,
            affected_package="curl",
            fix_status="unfixed"
        )
        db_session.add(image_cve2)
        db_session.commit()
        
        metrics = analyzer.get_release_security_metrics(sample_release.id)
        
        assert isinstance(metrics, SecurityMetrics)
        assert metrics.total_images == 1
        assert metrics.total_cves == 2
        assert metrics.unique_cves == 2
        assert metrics.critical_cves == 1
        assert metrics.high_cves == 1
        assert metrics.fixed_cves == 1
        assert metrics.unfixed_cves == 1
        assert metrics.risk_score > 0
    
    def test_get_release_security_metrics_no_data(self, db_session):
        """Test security metrics with no data."""
        analyzer = CVEAnalyzer()
        
        # Create empty release
        release = Release(version="empty", support_status="supported")
        db_session.add(release)
        db_session.flush()
        
        metrics = analyzer.get_release_security_metrics(release.id)
        
        assert metrics.total_images == 0
        assert metrics.total_cves == 0
        assert metrics.unique_cves == 0
        assert metrics.risk_score == 0.0
    
    def test_get_image_security_info(self, db_session, sample_release, sample_container_image, sample_cve, sample_image_cve):
        """Test getting image security information."""
        analyzer = CVEAnalyzer()
        
        images = analyzer.get_image_security_info(sample_release.id)
        
        assert len(images) == 1
        image_info = images[0]
        
        assert isinstance(image_info, ImageSecurityInfo)
        assert image_info.image_name == "openshift-ai/workbench"
        assert image_info.image_tag == "2.0.0"
        assert image_info.total_cves == 1
        assert image_info.high_cves == 1
        assert image_info.risk_level == "High"
    
    def test_get_cve_details(self, db_session, sample_release, sample_container_image, sample_cve, sample_image_cve):
        """Test getting CVE details."""
        analyzer = CVEAnalyzer()
        
        cves, total_count = analyzer.get_cve_details(sample_release.id)
        
        assert total_count == 1
        assert len(cves) == 1
        
        cve_info = cves[0]
        assert isinstance(cve_info, CVEInfo)
        assert cve_info.cve_id == "CVE-2024-12345"
        assert cve_info.severity == "High"
        assert cve_info.cvss_score == 7.5
        assert cve_info.affected_images_count == 1
        assert "openssl" in cve_info.affected_packages
    
    def test_get_cve_details_with_filters(self, db_session, sample_release, sample_container_image, sample_cve, sample_image_cve):
        """Test getting CVE details with filters."""
        analyzer = CVEAnalyzer()
        
        # Test severity filter
        cves, total_count = analyzer.get_cve_details(
            sample_release.id, 
            severity_filter=["Critical"]
        )
        assert len(cves) == 0  # Our sample CVE is High, not Critical
        
        cves, total_count = analyzer.get_cve_details(
            sample_release.id, 
            severity_filter=["High"]
        )
        assert len(cves) == 1
    
    def test_get_cve_details_with_pagination(self, db_session, sample_release, sample_container_image):
        """Test CVE details with pagination."""
        analyzer = CVEAnalyzer()
        
        # Create multiple CVEs
        for i in range(5):
            cve = CVE(
                cve_id=f"CVE-2024-{1000+i}",
                severity="Medium",
                cvss_score=5.0
            )
            db_session.add(cve)
            db_session.flush()
            
            image_cve = ImageCVE(
                image_id=sample_container_image.id,
                cve_id=cve.id,
                affected_package=f"package{i}"
            )
            db_session.add(image_cve)
        
        db_session.commit()
        
        # Test pagination
        cves, total_count = analyzer.get_cve_details(
            sample_release.id,
            limit=3,
            offset=0
        )
        
        assert total_count == 5
        assert len(cves) == 3
        
        # Test second page
        cves, total_count = analyzer.get_cve_details(
            sample_release.id,
            limit=3,
            offset=3
        )
        
        assert total_count == 5
        assert len(cves) == 2
    
    def test_get_cves_for_image(self, db_session, sample_container_image, sample_cve, sample_image_cve):
        """Test getting CVEs for a specific image."""
        analyzer = CVEAnalyzer()
        
        cves = analyzer.get_cves_for_image(sample_container_image.id)
        
        assert len(cves) == 1
        cve_info = cves[0]
        assert cve_info.cve_id == "CVE-2024-12345"
        assert cve_info.affected_images_count == 1
    
    def test_compare_releases(self, db_session):
        """Test comparing two releases."""
        analyzer = CVEAnalyzer()
        
        # Create two releases
        release1 = Release(version="1.0.0", support_status="supported")
        release2 = Release(version="2.0.0", support_status="supported")
        db_session.add_all([release1, release2])
        db_session.flush()
        
        # Add some test data for comparison
        image1 = ContainerImage(
            release_id=release1.id,
            image_name="test-image",
            image_tag="1.0.0"
        )
        image2 = ContainerImage(
            release_id=release2.id,
            image_name="test-image",
            image_tag="2.0.0"
        )
        db_session.add_all([image1, image2])
        db_session.flush()
        
        cve1 = CVE(cve_id="CVE-2024-1111", severity="High")
        cve2 = CVE(cve_id="CVE-2024-2222", severity="Medium")
        db_session.add_all([cve1, cve2])
        db_session.flush()
        
        # CVE in both releases
        image_cve1_1 = ImageCVE(image_id=image1.id, cve_id=cve1.id)
        image_cve2_1 = ImageCVE(image_id=image2.id, cve_id=cve1.id)
        
        # CVE only in release 2
        image_cve2_2 = ImageCVE(image_id=image2.id, cve_id=cve2.id)
        
        db_session.add_all([image_cve1_1, image_cve2_1, image_cve2_2])
        db_session.commit()
        
        comparison = analyzer.compare_releases(release1.id, release2.id)
        
        assert comparison["release_1"]["version"] == "1.0.0"
        assert comparison["release_2"]["version"] == "2.0.0"
        assert len(comparison["cve_changes"]["persistent"]) == 1  # CVE-2024-1111
        assert len(comparison["cve_changes"]["introduced"]) == 1  # CVE-2024-2222
        assert len(comparison["cve_changes"]["fixed"]) == 0
    
    def test_get_top_vulnerable_images(self, db_session, sample_release, sample_container_image, sample_cve, sample_image_cve):
        """Test getting top vulnerable images."""
        analyzer = CVEAnalyzer()
        
        # Create another image with more CVEs
        image2 = ContainerImage(
            release_id=sample_release.id,
            image_name="high-risk-image",
            image_tag="latest"
        )
        db_session.add(image2)
        db_session.flush()
        
        # Add multiple CVEs to second image
        for i in range(3):
            cve = CVE(
                cve_id=f"CVE-2024-{2000+i}",
                severity="Critical",
                cvss_score=9.0
            )
            db_session.add(cve)
            db_session.flush()
            
            image_cve = ImageCVE(
                image_id=image2.id,
                cve_id=cve.id
            )
            db_session.add(image_cve)
        
        db_session.commit()
        
        top_images = analyzer.get_top_vulnerable_images(sample_release.id, limit=5)
        
        assert len(top_images) == 2
        # Should be sorted by risk (Critical CVEs first)
        assert top_images[0].image_name == "high-risk-image"
        assert top_images[0].critical_cves == 3
        assert top_images[1].image_name == "openshift-ai/workbench"
        assert top_images[1].high_cves == 1


class TestSecurityMetrics:
    """Test cases for SecurityMetrics class."""
    
    def test_severity_distribution(self):
        """Test severity distribution property."""
        metrics = SecurityMetrics(
            critical_cves=5,
            high_cves=10,
            medium_cves=15,
            low_cves=20,
            unknown_severity_cves=3
        )
        
        distribution = metrics.severity_distribution
        
        assert distribution["Critical"] == 5
        assert distribution["High"] == 10
        assert distribution["Medium"] == 15
        assert distribution["Low"] == 20
        assert distribution["Unknown"] == 3
    
    def test_fix_status_distribution(self):
        """Test fix status distribution property."""
        metrics = SecurityMetrics(
            total_cves=100,
            fixed_cves=60,
            unfixed_cves=30
        )
        
        distribution = metrics.fix_status_distribution
        
        assert distribution["Fixed"] == 60
        assert distribution["Unfixed"] == 30
        assert distribution["Unknown"] == 10  # 100 - 60 - 30
    
    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        # Test with no CVEs
        metrics = SecurityMetrics(total_cves=0)
        assert metrics.risk_score == 0.0
        
        # Test with all critical CVEs
        metrics = SecurityMetrics(
            total_cves=10,
            critical_cves=10
        )
        assert metrics.risk_score == 100.0
        
        # Test with mixed severity
        metrics = SecurityMetrics(
            total_cves=10,
            critical_cves=2,  # 2 * 10 = 20
            high_cves=3,      # 3 * 5 = 15
            medium_cves=3,    # 3 * 2 = 6
            low_cves=2        # 2 * 1 = 2
        )
        # Total weighted score: 20 + 15 + 6 + 2 = 43
        # Max possible: 10 * 10 = 100
        # Risk score: 43/100 * 100 = 43.0
        assert metrics.risk_score == 43.0


class TestCVEInfo:
    """Test cases for CVEInfo class."""
    
    def test_cve_info_creation(self):
        """Test CVEInfo creation."""
        cve_info = CVEInfo(
            cve_id="CVE-2024-1234",
            severity="High",
            cvss_score=7.5,
            description="Test vulnerability",
            affected_images_count=5
        )
        
        assert cve_info.cve_id == "CVE-2024-1234"
        assert cve_info.severity == "High"
        assert cve_info.cvss_score == 7.5
        assert cve_info.affected_packages == []  # Default empty list
    
    def test_cve_info_with_packages(self):
        """Test CVEInfo with affected packages."""
        packages = ["openssl", "curl", "nginx"]
        cve_info = CVEInfo(
            cve_id="CVE-2024-1234",
            affected_packages=packages
        )
        
        assert cve_info.affected_packages == packages


class TestImageSecurityInfo:
    """Test cases for ImageSecurityInfo class."""
    
    def test_display_name_with_tag(self):
        """Test display name generation with tag."""
        info = ImageSecurityInfo(
            image_id=1,
            image_name="test/image",
            image_tag="1.0.0"
        )
        
        assert info.display_name == "test/image:1.0.0"
    
    def test_display_name_without_tag(self):
        """Test display name generation without tag."""
        info = ImageSecurityInfo(
            image_id=1,
            image_name="test/image"
        )
        
        assert info.display_name == "test/image"
    
    def test_risk_level_critical(self):
        """Test risk level calculation for critical CVEs."""
        info = ImageSecurityInfo(
            image_id=1,
            image_name="test/image",
            critical_cves=1
        )
        
        assert info.risk_level == "Critical"
    
    def test_risk_level_high(self):
        """Test risk level calculation for high CVEs."""
        info = ImageSecurityInfo(
            image_id=1,
            image_name="test/image",
            high_cves=1
        )
        
        assert info.risk_level == "High"
    
    def test_risk_level_medium(self):
        """Test risk level calculation for medium CVEs."""
        info = ImageSecurityInfo(
            image_id=1,
            image_name="test/image",
            medium_cves=1
        )
        
        assert info.risk_level == "Medium"
    
    def test_risk_level_low(self):
        """Test risk level calculation for low CVEs."""
        info = ImageSecurityInfo(
            image_id=1,
            image_name="test/image",
            low_cves=1
        )
        
        assert info.risk_level == "Low"
    
    def test_risk_level_minimal(self):
        """Test risk level calculation for no CVEs."""
        info = ImageSecurityInfo(
            image_id=1,
            image_name="test/image"
        )
        
        assert info.risk_level == "Minimal"