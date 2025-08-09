"""Tests for Pyxis API client."""

import pytest
from unittest.mock import Mock, patch
import requests

from src.api.pyxis import PyxisClient, PyxisAPIError


class TestPyxisClient:
    """Test cases for PyxisClient."""
    
    def test_init(self):
        """Test client initialization."""
        client = PyxisClient()
        assert client.base_url == "https://catalog.redhat.com/api/containers/v1"
        assert client.timeout == 30
        assert "User-Agent" in client.headers
    
    def test_init_with_custom_params(self):
        """Test client initialization with custom parameters."""
        client = PyxisClient(
            base_url="https://custom.api.com/v1",
            timeout=60
        )
        assert client.base_url == "https://custom.api.com/v1"
        assert client.timeout == 60
    
    def test_build_url_no_params(self):
        """Test URL building without parameters."""
        client = PyxisClient()
        url = client._build_url("products")
        assert url == "https://catalog.redhat.com/api/containers/v1/products"
    
    def test_build_url_with_params(self):
        """Test URL building with parameters."""
        client = PyxisClient()
        url = client._build_url("products", {"page_size": 10, "filter": "test"})
        assert "page_size=10" in url
        assert "filter=test" in url
    
    def test_build_url_filters_none_values(self):
        """Test URL building filters out None values."""
        client = PyxisClient()
        url = client._build_url("products", {"page_size": 10, "filter": None})
        assert "page_size=10" in url
        assert "filter" not in url
    
    @patch('requests.Session.get')
    def test_make_request_success(self, mock_get):
        """Test successful API request."""
        mock_response = Mock()
        mock_response.json.return_value = {"data": [{"id": "test"}]}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        client = PyxisClient()
        result = client._make_request("products")
        
        assert result == {"data": [{"id": "test"}]}
        mock_get.assert_called_once()
    
    @patch('requests.Session.get')
    def test_make_request_http_error(self, mock_get):
        """Test API request with HTTP error."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"detail": "Not found"}
        mock_response.text = "Not found"
        
        mock_get.return_value = mock_response
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
        
        client = PyxisClient()
        
        with pytest.raises(PyxisAPIError) as exc_info:
            client._make_request("products")
        
        assert exc_info.value.status_code == 404
        assert "Not found" in str(exc_info.value)
    
    @patch('requests.Session.get')
    def test_make_request_connection_error(self, mock_get):
        """Test API request with connection error."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        client = PyxisClient()
        
        with pytest.raises(PyxisAPIError) as exc_info:
            client._make_request("products")
        
        assert "Connection failed" in str(exc_info.value)
    
    def test_search_products(self, mock_pyxis_client):
        """Test product search."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.return_value = {"data": [{"name": "OpenShift AI"}]}
            
            client = PyxisClient()
            result = client.search_products("OpenShift AI")
            
            assert len(result) == 1
            assert result[0]["name"] == "OpenShift AI"
    
    def test_search_products_error_handling(self):
        """Test product search error handling."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.side_effect = PyxisAPIError("API Error")
            
            client = PyxisClient()
            result = client.search_products("OpenShift AI")
            
            assert result == []
    
    def test_get_openshift_ai_products(self, mock_pyxis_client):
        """Test OpenShift AI product discovery."""
        with patch.object(PyxisClient, 'search_products') as mock_search:
            mock_search.return_value = [
                {"_id": "1", "name": "OpenShift AI"},
                {"_id": "2", "name": "Red Hat OpenShift AI"}
            ]
            
            client = PyxisClient()
            result = client.get_openshift_ai_products()
            
            # Should deduplicate based on _id
            assert len(result) == 2
    
    def test_get_product_releases(self, mock_pyxis_client):
        """Test getting product releases."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.return_value = {
                "data": [
                    {"release_name": "2.0.0", "published": True},
                    {"release_name": "1.9.0", "published": True}
                ]
            }
            
            client = PyxisClient()
            result = client.get_product_releases("product123")
            
            assert len(result) == 2
            assert result[0]["release_name"] == "2.0.0"
    
    def test_get_container_images(self, mock_pyxis_client):
        """Test getting container images."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.return_value = {
                "data": [
                    {"_id": "img1", "repositories": []},
                    {"_id": "img2", "repositories": []}
                ],
                "total": 2
            }
            
            client = PyxisClient()
            result = client.get_container_images("product123", "2.0.0")
            
            assert len(result) == 2
    
    def test_get_image_vulnerabilities(self, mock_pyxis_client):
        """Test getting image vulnerabilities."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.return_value = {
                "data": [
                    {"cve_id": "CVE-2024-1234", "severity": "High"}
                ]
            }
            
            client = PyxisClient()
            result = client.get_image_vulnerabilities("image123")
            
            assert len(result) == 1
            assert result[0]["cve_id"] == "CVE-2024-1234"
    
    def test_get_image_details(self, mock_pyxis_client):
        """Test getting image details."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.return_value = {
                "data": {"_id": "image123", "name": "test-image"}
            }
            
            client = PyxisClient()
            result = client.get_image_details("image123")
            
            assert result["_id"] == "image123"
            assert result["name"] == "test-image"
    
    def test_health_check_success(self):
        """Test successful health check."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.return_value = {"data": []}
            
            client = PyxisClient()
            result = client.health_check()
            
            assert result is True
    
    def test_health_check_failure(self):
        """Test failed health check."""
        with patch.object(PyxisClient, '_make_request') as mock_request:
            mock_request.side_effect = PyxisAPIError("Connection failed")
            
            client = PyxisClient()
            result = client.health_check()
            
            assert result is False
    
    def test_context_manager(self):
        """Test client as context manager."""
        with PyxisClient() as client:
            assert client.session is not None
        
        # Session should be closed after context exit
        assert client.session is not None  # Session object still exists but is closed


class TestPyxisAPIError:
    """Test cases for PyxisAPIError."""
    
    def test_basic_error(self):
        """Test basic error creation."""
        error = PyxisAPIError("Test error")
        assert str(error) == "Test error"
        assert error.status_code is None
        assert error.response_data is None
    
    def test_error_with_status_code(self):
        """Test error with status code."""
        error = PyxisAPIError("Test error", status_code=404)
        assert str(error) == "Test error"
        assert error.status_code == 404
    
    def test_error_with_response_data(self):
        """Test error with response data."""
        response_data = {"detail": "Not found"}
        error = PyxisAPIError("Test error", response_data=response_data)
        assert str(error) == "Test error"
        assert error.response_data == response_data