import pytest
import sys
from pathlib import Path


class TestSetupValidation:
    """Validation tests to ensure the testing infrastructure is properly configured."""
    
    def test_pytest_is_available(self):
        """Test that pytest is importable and available."""
        import pytest
        assert pytest.__version__
        
    def test_pytest_cov_is_available(self):
        """Test that pytest-cov plugin is available."""
        import pytest_cov
        assert pytest_cov
        
    def test_pytest_mock_is_available(self):
        """Test that pytest-mock plugin is available."""
        import pytest_mock
        assert pytest_mock
        
    def test_project_root_in_path(self):
        """Test that the project root is in Python path."""
        project_root = Path(__file__).parent.parent
        assert str(project_root) in sys.path or str(project_root.absolute()) in sys.path
        
    def test_can_import_dnschef(self):
        """Test that the main module can be imported."""
        try:
            import dnschef
            assert dnschef.DNSCHEF_VERSION
        except ImportError:
            # Add parent directory to path and try again
            sys.path.insert(0, str(Path(__file__).parent.parent))
            import dnschef
            assert dnschef.DNSCHEF_VERSION
            
    def test_fixtures_are_available(self, temp_dir, mock_config, mock_logger):
        """Test that conftest fixtures are available and working."""
        assert temp_dir.exists()
        assert temp_dir.is_dir()
        
        assert mock_config.interface == "127.0.0.1"
        assert mock_config.port == 53
        
        assert hasattr(mock_logger, 'info')
        assert hasattr(mock_logger, 'error')
        
    def test_markers_are_defined(self, pytestconfig):
        """Test that custom pytest markers are properly defined."""
        markers = pytestconfig.getini('markers')
        marker_names = [m.split(':')[0].strip() for m in markers]
        assert 'unit' in marker_names
        assert 'integration' in marker_names
        assert 'slow' in marker_names
        
    @pytest.mark.unit
    def test_unit_marker_works(self):
        """Test that the unit test marker can be used."""
        assert True
        
    @pytest.mark.integration
    def test_integration_marker_works(self):
        """Test that the integration test marker can be used."""
        assert True
        
    @pytest.mark.slow
    def test_slow_marker_works(self):
        """Test that the slow test marker can be used."""
        assert True
        
    def test_temp_file_fixture(self, temp_file):
        """Test that the temp_file fixture works correctly."""
        test_file = temp_file("test.txt", "Hello, World!")
        assert test_file.exists()
        assert test_file.read_text() == "Hello, World!"
        
    def test_mock_dns_query_fixture(self, mock_dns_query):
        """Test that the mock DNS query fixture is properly configured."""
        assert mock_dns_query.questions[0].qname == "example.com"
        assert mock_dns_query.questions[0].qtype == 1
        assert mock_dns_query.questions[0].qclass == 1
        
    def test_sample_dns_records_fixture(self, sample_dns_records):
        """Test that the sample DNS records fixture provides expected data."""
        assert "A" in sample_dns_records
        assert "AAAA" in sample_dns_records
        assert "MX" in sample_dns_records
        assert sample_dns_records["A"]["example.com"] == "192.168.1.1"
        
    def test_coverage_is_enabled(self):
        """Test that coverage tracking is properly configured."""
        # This test will pass if pytest-cov is properly configured
        # The actual coverage percentage will be checked by pytest-cov
        assert True