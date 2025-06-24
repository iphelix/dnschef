import pytest
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file within the temp directory."""
    def _temp_file(filename="test_file.txt", content=""):
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path
    return _temp_file


@pytest.fixture
def mock_config():
    """Create a mock configuration object."""
    config = Mock()
    config.interface = "127.0.0.1"
    config.port = 53
    config.tcp = False
    config.ipv6 = False
    config.file = None
    config.fakedomains = {}
    config.truedomains = {}
    config.nameservers = ["8.8.8.8", "8.8.4.4"]
    return config


@pytest.fixture
def mock_dns_query():
    """Create a mock DNS query object."""
    query = Mock()
    query.questions = [Mock()]
    query.questions[0].qname = "example.com"
    query.questions[0].qtype = 1  # A record
    query.questions[0].qclass = 1  # IN class
    return query


@pytest.fixture
def mock_socket():
    """Create a mock socket object."""
    socket_mock = MagicMock()
    socket_mock.sendto = Mock(return_value=None)
    socket_mock.recvfrom = Mock(return_value=(b"mock_response", ("127.0.0.1", 53)))
    socket_mock.close = Mock(return_value=None)
    return socket_mock


@pytest.fixture
def mock_logger():
    """Create a mock logger object."""
    logger = Mock()
    logger.info = Mock()
    logger.debug = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.critical = Mock()
    return logger


@pytest.fixture
def dns_server_config():
    """Create a basic DNS server configuration dictionary."""
    return {
        "interface": "0.0.0.0",
        "port": 53,
        "tcp": False,
        "ipv6": False,
        "nameservers": ["8.8.8.8"],
        "fakedomains": {
            "example.com": "192.168.1.100"
        },
        "truedomains": {}
    }


@pytest.fixture
def sample_dns_records():
    """Provide sample DNS records for testing."""
    return {
        "A": {
            "example.com": "192.168.1.1",
            "test.com": "10.0.0.1"
        },
        "AAAA": {
            "example.com": "2001:db8::1",
            "test.com": "2001:db8::2"
        },
        "MX": {
            "example.com": "10 mail.example.com",
            "test.com": "20 mail.test.com"
        },
        "CNAME": {
            "www.example.com": "example.com",
            "alias.test.com": "test.com"
        },
        "NS": {
            "example.com": "ns1.example.com",
            "test.com": "ns1.test.com"
        },
        "TXT": {
            "example.com": "v=spf1 include:_spf.example.com ~all",
            "test.com": "test-txt-record"
        }
    }


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables and state before each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def capture_stdout(monkeypatch):
    """Capture stdout for testing print statements."""
    import io
    import sys
    
    captured_output = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', captured_output)
    yield captured_output
    monkeypatch.undo()


@pytest.fixture
def mock_args():
    """Create mock command line arguments."""
    args = Mock()
    args.interface = "127.0.0.1"
    args.port = 53
    args.tcp = False
    args.ipv6 = False
    args.file = None
    args.fakeip = None
    args.fakeipv6 = None
    args.fakedomains = None
    args.fakealias = None
    args.fakens = None
    args.fakemx = None
    args.faketxt = None
    args.fakecname = None
    args.truedomains = None
    args.nameservers = "8.8.8.8"
    args.q = False
    return args