"""Pytest configuration and fixtures for OpenShift AI Security Dashboard."""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime, date
from unittest.mock import Mock, patch

from src.database.connection import create_database_engine, get_db_session
from src.database.models import Base, Release, ContainerImage, CVE, ImageCVE
from src.config import TestConfig


@pytest.fixture(scope="session")
def test_config():
    """Test configuration fixture."""
    return TestConfig()


@pytest.fixture(scope="function")
def test_db_engine():
    """Create a test database engine."""
    engine = create_database_engine(test_mode=True)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def db_session(test_db_engine):
    """Create a test database session."""
    with patch('src.database.connection.get_engine', return_value=test_db_engine):
        with get_db_session() as session:
            yield session


@pytest.fixture
def sample_release(db_session):
    """Create a sample release for testing."""
    release = Release(
        version="2.0.0",
        release_date=date(2024, 6, 1),
        support_status="supported"
    )
    db_session.add(release)
    db_session.flush()
    return release


@pytest.fixture
def sample_container_image(db_session, sample_release):
    """Create a sample container image for testing."""
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
    db_session.flush()
    return image


@pytest.fixture
def sample_cve(db_session):
    """Create a sample CVE for testing."""
    cve = CVE(
        cve_id="CVE-2024-12345",
        severity="High",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        description="Sample high severity vulnerability",
        published_date=date(2024, 5, 15),
        modified_date=date(2024, 5, 20)
    )
    db_session.add(cve)
    db_session.flush()
    return cve


@pytest.fixture
def sample_image_cve(db_session, sample_container_image, sample_cve):
    """Create a sample image-CVE relationship for testing."""
    image_cve = ImageCVE(
        image_id=sample_container_image.id,
        cve_id=sample_cve.id,
        affected_package="openssl",
        fixed_version="1.1.1k-1",
        fix_status="fixed"
    )
    db_session.add(image_cve)
    db_session.flush()
    return image_cve


@pytest.fixture
def mock_pyxis_client():
    """Mock Pyxis API client."""
    client = Mock()
    
    # Mock successful responses
    client.get_openshift_ai_products.return_value = [
        {
            "_id": "product123",
            "name": "Red Hat OpenShift AI",
            "description": "OpenShift AI product"
        }
    ]
    
    client.get_product_releases.return_value = [
        {
            "release_name": "2.0.0",
            "published": True,
            "support_status": "supported",
            "release_date": "2024-06-01T00:00:00Z"
        }
    ]
    
    client.get_container_images.return_value = [
        {
            "_id": "image123",
            "repositories": [{
                "repository": "openshift-ai/workbench",
                "tags": [{"name": "2.0.0"}],
                "published_url": "registry.redhat.io/openshift-ai/workbench:2.0.0"
            }],
            "architecture": "amd64",
            "uncompressed_size_bytes": 1000000000,
            "docker_image_digest": "sha256:abc123..."
        }
    ]
    
    client.get_image_vulnerabilities.return_value = [
        {
            "cve_id": "CVE-2024-12345",
            "package": "openssl",
            "fixed_version": "1.1.1k-1",
            "fix_state": "fixed"
        }
    ]
    
    client.health_check.return_value = True
    
    return client


@pytest.fixture
def mock_security_client():
    """Mock Security Data API client."""
    client = Mock()
    
    # Mock CVE details
    client.get_cve_details.return_value = {
        "cve_id": "CVE-2024-12345",
        "threat_severity": "High",
        "cvss": {
            "cvss_base_score": 7.5,
            "cvss_scoring_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        "details": ["Sample high severity vulnerability"],
        "public_date": "2024-05-15T00:00:00Z",
        "last_modified_date": "2024-05-20T00:00:00Z"
    }
    
    client.get_cve_metrics.return_value = {
        "cve_id": "CVE-2024-12345",
        "severity": "High",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Sample high severity vulnerability",
        "published_date": "2024-05-15T00:00:00Z",
        "modified_date": "2024-05-20T00:00:00Z"
    }
    
    client.get_multiple_cve_details.return_value = {
        "CVE-2024-12345": {
            "cve_id": "CVE-2024-12345",
            "threat_severity": "High",
            "cvss": {"cvss_base_score": 7.5}
        }
    }
    
    client.health_check.return_value = True
    
    return client


@pytest.fixture
def temp_export_dir():
    """Create a temporary directory for exports."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def mock_streamlit():
    """Mock Streamlit components for testing."""
    with patch('streamlit.session_state', {}):
        with patch('streamlit.secrets', {}):
            yield


# Pytest configuration
def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "api: mark test as requiring external APIs"
    )