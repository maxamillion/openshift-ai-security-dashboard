"""Tests for database models."""

import pytest
from datetime import datetime, date

from src.database.models import Release, ContainerImage, CVE, ImageCVE, Errata, CVEErrata, Snapshot


class TestRelease:
    """Test cases for Release model."""
    
    def test_release_creation(self, db_session):
        """Test creating a release."""
        release = Release(
            version="2.0.0",
            release_date=date(2024, 6, 1),
            support_status="supported"
        )
        
        db_session.add(release)
        db_session.commit()
        
        assert release.id is not None
        assert release.version == "2.0.0"
        assert release.release_date == date(2024, 6, 1)
        assert release.support_status == "supported"
        assert release.created_at is not None
        assert release.updated_at is not None
    
    def test_release_repr(self, db_session):
        """Test release string representation."""
        release = Release(
            version="2.0.0",
            support_status="supported"
        )
        
        db_session.add(release)
        db_session.flush()
        
        repr_str = repr(release)
        assert "2.0.0" in repr_str
        assert "supported" in repr_str


class TestContainerImage:
    """Test cases for ContainerImage model."""
    
    def test_container_image_creation(self, db_session, sample_release):
        """Test creating a container image."""
        image = ContainerImage(
            release_id=sample_release.id,
            image_name="openshift-ai/workbench",
            image_tag="2.0.0",
            image_digest="sha256:abc123...",
            registry_path="registry.redhat.io/ubi8/ubi",
            architecture="amd64",
            size_bytes=1000000000
        )
        
        db_session.add(image)
        db_session.commit()
        
        assert image.id is not None
        assert image.release_id == sample_release.id
        assert image.image_name == "openshift-ai/workbench"
        assert image.image_tag == "2.0.0"
        assert image.size_bytes == 1000000000
    
    def test_container_image_relationship(self, db_session, sample_release):
        """Test container image relationship with release."""
        image = ContainerImage(
            release_id=sample_release.id,
            image_name="test-image",
            image_tag="latest"
        )
        
        db_session.add(image)
        db_session.commit()
        
        # Test relationship
        assert image.release == sample_release
        assert image in sample_release.container_images


class TestCVE:
    """Test cases for CVE model."""
    
    def test_cve_creation(self, db_session):
        """Test creating a CVE."""
        cve = CVE(
            cve_id="CVE-2024-12345",
            severity="High",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description="Test vulnerability",
            published_date=date(2024, 5, 15),
            modified_date=date(2024, 5, 20)
        )
        
        db_session.add(cve)
        db_session.commit()
        
        assert cve.id is not None
        assert cve.cve_id == "CVE-2024-12345"
        assert cve.severity == "High"
        assert cve.cvss_score == 7.5
        assert cve.published_date == date(2024, 5, 15)
    
    def test_cve_url_property(self, db_session):
        """Test CVE URL property."""
        cve = CVE(cve_id="CVE-2024-12345")
        
        expected_url = "https://access.redhat.com/security/cve/CVE-2024-12345"
        assert cve.url == expected_url
    
    def test_cve_repr(self, db_session):
        """Test CVE string representation."""
        cve = CVE(
            cve_id="CVE-2024-12345",
            severity="High"
        )
        
        db_session.add(cve)
        db_session.flush()
        
        repr_str = repr(cve)
        assert "CVE-2024-12345" in repr_str
        assert "High" in repr_str


class TestImageCVE:
    """Test cases for ImageCVE model."""
    
    def test_image_cve_creation(self, db_session, sample_container_image, sample_cve):
        """Test creating an image-CVE relationship."""
        image_cve = ImageCVE(
            image_id=sample_container_image.id,
            cve_id=sample_cve.id,
            affected_package="openssl",
            fixed_version="1.1.1k-1",
            fix_status="fixed"
        )
        
        db_session.add(image_cve)
        db_session.commit()
        
        assert image_cve.id is not None
        assert image_cve.image_id == sample_container_image.id
        assert image_cve.cve_id == sample_cve.id
        assert image_cve.affected_package == "openssl"
        assert image_cve.fix_status == "fixed"
    
    def test_image_cve_relationships(self, db_session, sample_container_image, sample_cve):
        """Test image-CVE relationships."""
        image_cve = ImageCVE(
            image_id=sample_container_image.id,
            cve_id=sample_cve.id,
            affected_package="openssl"
        )
        
        db_session.add(image_cve)
        db_session.commit()
        
        # Test relationships
        assert image_cve.container_image == sample_container_image
        assert image_cve.cve == sample_cve
        assert image_cve in sample_container_image.image_cves
        assert image_cve in sample_cve.image_cves
    
    def test_image_cve_unique_constraint(self, db_session, sample_container_image, sample_cve):
        """Test unique constraint on image-CVE-package combination."""
        image_cve1 = ImageCVE(
            image_id=sample_container_image.id,
            cve_id=sample_cve.id,
            affected_package="openssl"
        )
        
        db_session.add(image_cve1)
        db_session.commit()
        
        # Try to add duplicate
        image_cve2 = ImageCVE(
            image_id=sample_container_image.id,
            cve_id=sample_cve.id,
            affected_package="openssl"
        )
        
        db_session.add(image_cve2)
        
        with pytest.raises(Exception):  # Should raise integrity error
            db_session.commit()


class TestErrata:
    """Test cases for Errata model."""
    
    def test_errata_creation(self, db_session):
        """Test creating an errata."""
        errata = Errata(
            advisory_id="RHSA-2024:12345",
            advisory_type="Security Advisory",
            severity="Important",
            synopsis="Security update for openssl",
            description="An update for openssl packages that fixes security vulnerabilities",
            issue_date=date(2024, 5, 20)
        )
        
        db_session.add(errata)
        db_session.commit()
        
        assert errata.id is not None
        assert errata.advisory_id == "RHSA-2024:12345"
        assert errata.advisory_type == "Security Advisory"
        assert errata.severity == "Important"
        assert errata.issue_date == date(2024, 5, 20)
    
    def test_errata_url_property(self, db_session):
        """Test errata URL property."""
        errata = Errata(advisory_id="RHSA-2024:12345")
        
        expected_url = "https://access.redhat.com/errata/RHSA-2024:12345"
        assert errata.url == expected_url


class TestCVEErrata:
    """Test cases for CVEErrata model."""
    
    def test_cve_errata_creation(self, db_session, sample_cve):
        """Test creating a CVE-errata relationship."""
        errata = Errata(
            advisory_id="RHSA-2024:12345",
            advisory_type="Security Advisory"
        )
        db_session.add(errata)
        db_session.flush()
        
        cve_errata = CVEErrata(
            cve_id=sample_cve.id,
            errata_id=errata.id
        )
        
        db_session.add(cve_errata)
        db_session.commit()
        
        assert cve_errata.id is not None
        assert cve_errata.cve_id == sample_cve.id
        assert cve_errata.errata_id == errata.id
    
    def test_cve_errata_relationships(self, db_session, sample_cve):
        """Test CVE-errata relationships."""
        errata = Errata(advisory_id="RHSA-2024:12345")
        db_session.add(errata)
        db_session.flush()
        
        cve_errata = CVEErrata(
            cve_id=sample_cve.id,
            errata_id=errata.id
        )
        
        db_session.add(cve_errata)
        db_session.commit()
        
        # Test relationships
        assert cve_errata.cve == sample_cve
        assert cve_errata.errata == errata
        assert cve_errata in sample_cve.cve_errata
        assert cve_errata in errata.cve_errata


class TestSnapshot:
    """Test cases for Snapshot model."""
    
    def test_snapshot_creation(self, db_session, sample_release):
        """Test creating a snapshot."""
        snapshot = Snapshot(
            release_id=sample_release.id,
            snapshot_date=datetime.utcnow(),
            total_images=10,
            total_cves=50,
            critical_cves=5,
            high_cves=15,
            medium_cves=20,
            low_cves=10,
            snapshot_data={
                "analysis_date": datetime.utcnow().isoformat(),
                "data_sources": ["pyxis", "security_data_api"]
            }
        )
        
        db_session.add(snapshot)
        db_session.commit()
        
        assert snapshot.id is not None
        assert snapshot.release_id == sample_release.id
        assert snapshot.total_images == 10
        assert snapshot.total_cves == 50
        assert snapshot.critical_cves == 5
        assert isinstance(snapshot.snapshot_data, dict)
    
    def test_snapshot_relationship(self, db_session, sample_release):
        """Test snapshot relationship with release."""
        snapshot = Snapshot(
            release_id=sample_release.id,
            snapshot_date=datetime.utcnow(),
            total_images=5
        )
        
        db_session.add(snapshot)
        db_session.commit()
        
        # Test relationship
        assert snapshot.release == sample_release
        assert snapshot in sample_release.snapshots