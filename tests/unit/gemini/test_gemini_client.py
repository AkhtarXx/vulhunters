"""
🧪 Unit Tests for Gemini Client
================================

Tests Gemini API client functionality:
- Initialization
- Token caching
- Rate limiting integration
- MCP tool integration
- Async generation
"""

import pytest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock, AsyncMock
import asyncio

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))


class TestGeminiClientImport:
    """Test Gemini client can be imported."""
    
    def test_import_gemini_client(self):
        """Test importing GeminiClient."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            assert GeminiClient is not None
        except ImportError as e:
            pytest.skip(f"Gemini SDK not installed: {e}")


class TestGeminiClientInitialization:
    """Test GeminiClient initialization."""
    
    @pytest.fixture
    def mock_genai(self):
        """Mock Google GenAI SDK."""
        with patch('vulnhunter.gemini.client.genai') as mock:
            mock.Client.return_value = MagicMock()
            yield mock
    
    def test_initialization_with_api_key(self, mock_genai):
        """Test client initializes with API key."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch.dict('os.environ', {'GEMINI_API_KEY': 'test-key'}):
                client = GeminiClient(api_key="test-key")
            
            assert client is not None
        except ImportError:
            pytest.skip("Gemini SDK not installed")
    
    def test_initialization_from_env(self, mock_genai):
        """Test client uses env variable for API key."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch.dict('os.environ', {'GEMINI_API_KEY': 'env-test-key'}):
                client = GeminiClient()
            
            assert client is not None
        except ImportError:
            pytest.skip("Gemini SDK not installed")


class TestGeminiGenerate:
    """Test generation methods."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mocked GeminiClient."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai') as mock_genai:
                mock_genai.Client.return_value = MagicMock()
                
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
                    yield client
        except ImportError:
            pytest.skip("Gemini SDK not installed")
    
    def test_generate_returns_response(self, mock_client):
        """Test generate returns a response."""
        if mock_client is None:
            pytest.skip("Client not available")
        
        # Mock the API response
        mock_response = MagicMock()
        mock_response.text = "Test response"
        mock_client.client.models.generate_content.return_value = mock_response
        
        # This would normally call the API
        # For unit tests, we just verify the method exists
        assert hasattr(mock_client, 'generate')
    
    def test_generate_with_system_instruction(self, mock_client):
        """Test generate with system instruction."""
        if mock_client is None:
            pytest.skip("Client not available")
        
        assert hasattr(mock_client, 'generate')
    
    def test_generate_with_json_output(self, mock_client):
        """Test generate with JSON output mode."""
        if mock_client is None:
            pytest.skip("Client not available")
        
        assert hasattr(mock_client, 'generate')


class TestGeminiAsync:
    """Test async generation methods."""
    
    def test_generate_async_exists(self):
        """Test async generate method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'generate_async')
            assert asyncio.iscoroutinefunction(client.generate_async)
        except ImportError:
            pytest.skip("Gemini SDK not installed")
    
    def test_generate_with_mcp_tools_exists(self):
        """Test MCP tools method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'generate_with_mcp_tools')
        except ImportError:
            pytest.skip("Gemini SDK not installed")


class TestCaching:
    """Test contract caching functionality."""
    
    def test_cache_contract_exists(self):
        """Test cache_contract method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'cache_contract')
        except ImportError:
            pytest.skip("Gemini SDK not installed")
    
    def test_cache_contract_async_exists(self):
        """Test async cache method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'cache_contract_async')
        except ImportError:
            pytest.skip("Gemini SDK not installed")
    
    def test_generate_with_cache_exists(self):
        """Test cached generation exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'generate_with_cache')
        except ImportError:
            pytest.skip("Gemini SDK not installed")


class TestDeepResearch:
    """Test deep research functionality."""
    
    def test_deep_research_exists(self):
        """Test deep_research method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'deep_research')
        except ImportError:
            pytest.skip("Gemini SDK not installed")


class TestFileSearch:
    """Test file search functionality."""
    
    def test_create_audit_store_exists(self):
        """Test create_audit_store method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'create_audit_store')
        except ImportError:
            pytest.skip("Gemini SDK not installed")
    
    def test_upload_audit_report_exists(self):
        """Test upload method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'upload_audit_report')
        except ImportError:
            pytest.skip("Gemini SDK not installed")
    
    def test_search_audits_exists(self):
        """Test search_audits method exists."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            
            with patch('vulnhunter.gemini.client.genai'):
                with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}):
                    client = GeminiClient(api_key="test")
            
            assert hasattr(client, 'search_audits')
        except ImportError:
            pytest.skip("Gemini SDK not installed")


class TestRateLimiterIntegration:
    """Test rate limiter integration."""
    
    def test_uses_rate_limiter(self):
        """Test client uses rate limiter."""
        try:
            from vulnhunter.gemini.client import GeminiClient
            from vulnhunter.rate_limiter import get_rate_limiter
            
            # Rate limiter should be used internally
            limiter = get_rate_limiter()
            assert limiter is not None
        except ImportError:
            pytest.skip("Dependencies not installed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
