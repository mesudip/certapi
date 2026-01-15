import pytest
from unittest.mock import Mock, patch
import requests
from certapi.http.HttpClientBase import HttpClientBase
from certapi.errors import NetworkError, CertApiException


class TestHttpErrorHandling:
    """Test suite for HTTP error handling in HttpClientBase"""

    @pytest.fixture
    def http_client(self):
        """Create a basic HttpClientBase instance for testing"""
        return HttpClientBase(
            base_url="https://example.com", headers={"Content-Type": "application/json"}, auto_retry=True
        )

    def test_connection_reset_error_handling(self, http_client):
        """Test that ConnectionResetError is properly caught and converted to NetworkError"""
        with patch.object(http_client.session, "request") as mock_request:
            # Simulate a ConnectionResetError wrapped in requests.exceptions.ConnectionError
            connection_reset = ConnectionResetError(104, "Connection reset by peer")
            mock_request.side_effect = requests.exceptions.ConnectionError(connection_reset)

            with pytest.raises(NetworkError) as exc_info:
                http_client._req("GET", "https://example.com/test", "Test Step")

            # Verify the NetworkError is properly created
            error = exc_info.value
            assert error.can_retry is True
            assert "Network connection error" in error.message
            assert error.detail["errorType"] == "ConnectionError"

    def test_connection_error_is_retriable(self, http_client):
        """Test that connection errors are marked as retriable"""
        with patch.object(http_client.session, "request") as mock_request:
            mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")

            with pytest.raises(NetworkError) as exc_info:
                http_client._req("GET", "https://example.com/test", "Test Step")

            error = exc_info.value
            assert error.can_retry is True
            assert hasattr(error, "retry_delay")
            assert error.retry_delay == 4  # Default retry delay

    def test_timeout_error_is_retriable(self, http_client):
        """Test that timeout errors are marked as retriable"""
        with patch.object(http_client.session, "request") as mock_request:
            mock_request.side_effect = requests.exceptions.Timeout("Request timed out")

            with pytest.raises(NetworkError) as exc_info:
                http_client._req("GET", "https://example.com/test", "Test Step")

            error = exc_info.value
            assert error.can_retry is True
            assert hasattr(error, "retry_delay")

    def test_retry_uses_exception_delay(self, http_client):
        """Test that retry mechanism uses the delay from the exception"""
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:  # Fail first 2 times
                raise requests.exceptions.ConnectionError("Connection failed")
            # Success on 3rd attempt
            mock_response = Mock()
            mock_response.status_code = 200
            return mock_response

        with patch.object(http_client.session, "request", side_effect=side_effect):
            with patch("time.sleep") as mock_sleep:
                result = http_client._req_with_retry("GET", "https://example.com/test", "Test Step", retries=2)

                assert result.status_code == 200
                # Should have slept twice (after 1st and 2nd failures)
                assert mock_sleep.call_count == 2
                # Should use default delay of 4 seconds
                mock_sleep.assert_called_with(4)

    def test_retry_exhausted_marks_non_retriable(self, http_client):
        """Test that after exhausting retries, error is marked as non-retriable"""
        with patch.object(http_client.session, "request") as mock_request:
            mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")

            with pytest.raises(NetworkError) as exc_info:
                http_client._req_with_retry("GET", "https://example.com/test", "Test Step", retries=1)

            error = exc_info.value
            # After retries are exhausted, can_retry should be False
            assert error.can_retry is False

    def test_no_retry_when_auto_retry_false(self, http_client):
        """Test that retry doesn't happen when auto_retry is False"""
        http_client.auto_retry = False
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise requests.exceptions.ConnectionError("Connection failed")

        with patch.object(http_client.session, "request", side_effect=side_effect):
            with pytest.raises(NetworkError):
                http_client._req_with_retry("GET", "https://example.com/test", "Test Step", retries=2)

            # Should only be called once (no retries)
            assert call_count == 1

    def test_successful_request_no_error(self, http_client):
        """Test that successful requests don't raise errors"""
        with patch.object(http_client.session, "request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response

            result = http_client._req("GET", "https://example.com/test", "Test Step")

            assert result.status_code == 200

    def test_custom_retry_delay(self):
        """Test that custom retry delay can be set on exception"""
        exception = CertApiException("Test error")
        exception.retry_delay = 10
        exception.can_retry = True

        assert exception.retry_delay == 10
        assert exception.can_retry is True
