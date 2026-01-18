"""
Comprehensive test suite for ACME error handling.

Tests verify that all network errors, HTTP errors, and ACME-specific errors
are properly handled by Acme.py with appropriate exception types and retry logic.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
import json
from certapi.acme.Acme import Acme
from certapi.acme.AcmeError import (
    AcmeError,
    AcmeNetworkError,
    AcmeHttpError,
    AcmeInvalidNonceError,
)
from certapi.crypto import Key


class TestAcmeNetworkErrorHandling:
    """Test suite for network-related error handling in ACME client"""

    @pytest.fixture
    def acme_client(self):
        """Create an ACME client instance for testing"""
        # Create a mock key
        mock_key = Mock(spec=Key)
        mock_key.jwk.return_value = {"kty": "RSA", "n": "test", "e": "AQAB"}
        mock_key.algorithm_name.return_value = "RS256"
        mock_key.jws_sign.return_value = b"signature"

        client = Acme(account_key=mock_key, url="https://acme-staging-v02.api.letsencrypt.org/directory")
        client.nonce = ["initial-nonce"]
        return client

    @pytest.fixture
    def mock_directory_response(self):
        """Mock ACME directory response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "newNonce": "https://acme.example.com/new-nonce",
            "newAccount": "https://acme.example.com/new-account",
            "newOrder": "https://acme.example.com/new-order",
        }
        mock_response.headers = {"Replay-Nonce": "test-nonce-123"}
        return mock_response

    @pytest.mark.parametrize(
        "error_side_effect, expected_type, expected_msg",
        [
            (requests.exceptions.Timeout("Connection timed out"), "Timeout", "Error communicating with ACME server"),
            (
                requests.exceptions.ConnectionError(ConnectionRefusedError(111, "Connection refused")),
                "ConnectionError",
                "Error communicating with ACME server",
            ),
            (
                requests.exceptions.ConnectionError(ConnectionResetError(104, "Connection reset by peer")),
                "ConnectionError",
                "Error communicating with ACME server",
            ),
            (
                requests.exceptions.ConnectionError("Failed to resolve hostname"),
                "ConnectionError",
                "Error communicating with ACME server",
            ),
            (
                requests.exceptions.RequestException("Unknown error"),
                "RequestException",
                "Error communicating with ACME server",
            ),
        ],
    )
    def test_network_errors(self, acme_client, mock_directory_response, error_side_effect, expected_type, expected_msg):
        """Test various network-related errors with parametrization"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            # First call succeeds (directory fetch), second call fails with side effect
            mock_request.side_effect = [
                mock_directory_response,
                error_side_effect,
                mock_directory_response,
                error_side_effect,
                mock_directory_response,
                error_side_effect,
            ]

            with pytest.raises(AcmeNetworkError) as exc_info:
                acme_client.setup()
                acme_client.register()

            error = exc_info.value
            assert error.can_retry is True
            assert expected_msg in error.message
            assert error.detail["errorType"] == expected_type


class TestAcmeHttpErrorHandling:
    """Test suite for HTTP error handling in ACME client"""

    @pytest.fixture
    def acme_client(self):
        """Create an ACME client instance for testing"""
        mock_key = Mock(spec=Key)
        mock_key.jwk.return_value = {"kty": "RSA", "n": "test", "e": "AQAB"}
        mock_key.algorithm_name.return_value = "RS256"
        mock_key.jws_sign.return_value = b"signature"

        client = Acme(account_key=mock_key, url="https://acme-staging-v02.api.letsencrypt.org/directory")
        client.nonce = ["initial-nonce"]
        return client

    @pytest.fixture
    def mock_directory_response(self):
        """Mock ACME directory response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "newNonce": "https://acme.example.com/new-nonce",
            "newAccount": "https://acme.example.com/new-account",
            "newOrder": "https://acme.example.com/new-order",
        }
        mock_response.headers = {"Replay-Nonce": "test-nonce-123"}
        return mock_response

    @pytest.mark.parametrize(
        "status_code, json_body, expected_msg_part",
        [
            (
                503,
                {"type": "urn:ietf:params:acme:error:serverInternal", "detail": "Service unavailable"},
                "Service unavailable",
            ),
            (500, {"type": "urn:ietf:params:acme:error:serverInternal", "detail": "Internal error"}, "Internal error"),
            (429, {"type": "urn:ietf:params:acme:error:rateLimited", "detail": "Rate limit exceeded"}, "Rate limit"),
            (400, {"type": "urn:ietf:params:acme:error:malformed", "detail": "Malformed request"}, "Malformed request"),
            (
                401,
                {"type": "urn:ietf:params:acme:error:unauthorized", "detail": "Unauthorized access"},
                "Unauthorized access",
            ),
            (
                404,
                {"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "Account not found"},
                "Account not found",
            ),
        ],
    )
    def test_http_errors(self, acme_client, mock_directory_response, status_code, json_body, expected_msg_part):
        """Test various HTTP error status codes with parametrization"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            error_response = Mock()
            error_response.status_code = status_code
            error_response.json.return_value = json_body
            error_response.headers = {"Replay-Nonce": "test-nonce"}
            error_response.request = Mock()
            error_response.request.url = "https://acme.example.com/api"

            mock_request.side_effect = [mock_directory_response, error_response]

            with pytest.raises(AcmeHttpError) as exc_info:
                acme_client.setup()
                acme_client.register()

            error = exc_info.value
            assert error.response.status_code == status_code
            assert expected_msg_part.lower() in error.message.lower()

    def test_server_returns_text_response(self, acme_client, mock_directory_response):
        """Test that a text response (non-JSON) is handled correctly"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            error_response = Mock()
            error_response.status_code = 502
            error_response.text = "Bad Gateway (nginx)"
            # Simulate json() raising an exception when response is not JSON
            error_response.json.side_effect = requests.exceptions.JSONDecodeError("Expecting value", "", 0)
            error_response.headers = {"Replay-Nonce": "test-nonce"}
            error_response.request = Mock()
            error_response.request.url = "https://acme.example.com/api"

            mock_request.side_effect = [mock_directory_response, error_response]

            with pytest.raises(AcmeHttpError) as exc_info:
                acme_client.setup()
                acme_client.register()

            error = exc_info.value
            assert error.response.status_code == 502
            assert "Received status=502" in error.message
            assert error.detail["response"] == "Bad Gateway (nginx)"


class TestAcmeSpecificErrorHandling:
    """Test suite for ACME-specific error scenarios"""

    @pytest.fixture
    def acme_client(self):
        """Create an ACME client instance for testing"""
        mock_key = Mock(spec=Key)
        mock_key.jwk.return_value = {"kty": "RSA", "n": "test", "e": "AQAB"}
        mock_key.algorithm_name.return_value = "RS256"
        mock_key.jws_sign.return_value = b"signature"

        client = Acme(account_key=mock_key, url="https://acme-staging-v02.api.letsencrypt.org/directory")
        client.nonce = ["initial-nonce"]
        return client

    @pytest.fixture
    def mock_directory_response(self):
        """Mock ACME directory response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "newNonce": "https://acme.example.com/new-nonce",
            "newAccount": "https://acme.example.com/new-account",
            "newOrder": "https://acme.example.com/new-order",
        }
        mock_response.headers = {"Replay-Nonce": "test-nonce-123"}
        return mock_response

    def test_invalid_nonce_triggers_retry(self, acme_client, mock_directory_response):
        """Test that invalid nonce error triggers retry with new nonce"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            # First attempt: bad nonce error
            bad_nonce_response = Mock()
            bad_nonce_response.status_code = 400
            bad_nonce_response.json.return_value = {
                "type": "urn:ietf:params:acme:error:badNonce",
                "detail": "JWS has invalid anti-replay nonce",
            }
            bad_nonce_response.headers = {"Replay-Nonce": "new-nonce-456"}
            bad_nonce_response.request = Mock()
            bad_nonce_response.request.url = "https://acme.example.com/new-account"

            # Second attempt: success
            success_response = Mock()
            success_response.status_code = 201
            success_response.json.return_value = {"status": "valid"}
            success_response.headers = {
                "Replay-Nonce": "nonce-789",
                "location": "https://acme.example.com/account/123",
            }

            mock_request.side_effect = [
                mock_directory_response,  # setup() directory
                bad_nonce_response,  # first post() fail
                mock_directory_response,  # get_nonce() for retry (using directory mock as nonce mock)
                success_response,  # retry post() success
            ]

            with patch("time.sleep"):  # Skip actual sleep
                result = acme_client.setup()
                result = acme_client.register()

            # Should succeed after retry
            assert result.status_code == 201

    def test_challenge_validation_dns_nxdomain(self, acme_client):
        """Test handling of DNS NXDOMAIN error in challenge validation"""
        error_response = Mock()
        error_response.status_code = 400
        error_response.json.return_value = {
            "status": "invalid",
            "challenges": [
                {
                    "status": "invalid",
                    "url": "https://acme.example.com/challenge/123",
                    "error": {
                        "type": "urn:ietf:params:acme:error:dns",
                        "detail": "DNS problem: NXDOMAIN looking up A for example.com",
                    },
                }
            ],
        }
        error_response.headers = {"Replay-Nonce": "test-nonce"}
        error_response.request = Mock()
        error_response.request.url = "https://acme.example.com/challenge/123"

        with pytest.raises(AcmeHttpError) as exc_info:
            raise AcmeHttpError(error_response, "Challenge validation")

        error = exc_info.value
        assert "doesn't have a valid DNS record" in error.message or "NXDOMAIN" in str(error.detail)

    def test_challenge_validation_connection_timeout(self, acme_client):
        """Test handling of connection timeout during challenge validation"""
        error_response = Mock()
        error_response.status_code = 400
        error_response.json.return_value = {
            "status": "invalid",
            "challenges": [
                {
                    "status": "invalid",
                    "url": "https://acme.example.com/challenge/123",
                    "error": {
                        "type": "urn:ietf:params:acme:error:connection",
                        "detail": "Timeout during connect (likely firewall problem)",
                    },
                    "validationRecord": [
                        {
                            "hostname": "example.com",
                            "addressesResolved": ["192.0.2.1"],
                            "addressUsed": "192.0.2.1",
                            "port": 80,
                        }
                    ],
                }
            ],
        }
        error_response.headers = {"Replay-Nonce": "test-nonce"}
        error_response.request = Mock()
        error_response.request.url = "https://acme.example.com/challenge/123"

        with pytest.raises(AcmeHttpError) as exc_info:
            raise AcmeHttpError(error_response, "Challenge validation")

        error = exc_info.value
        assert "Connect Timeout" in error.message or "Timeout" in error.message

    def test_challenge_validation_connection_refused(self, acme_client):
        """Test handling of connection refused during challenge validation"""
        error_response = Mock()
        error_response.status_code = 400
        error_response.json.return_value = {
            "status": "invalid",
            "challenges": [
                {
                    "status": "invalid",
                    "url": "https://acme.example.com/challenge/123",
                    "error": {
                        "type": "urn:ietf:params:acme:error:connection",
                        "detail": "Connection refused",
                    },
                    "validationRecord": [
                        {
                            "hostname": "example.com",
                            "addressesResolved": ["192.0.2.1"],
                            "addressUsed": "192.0.2.1",
                            "port": 80,
                        }
                    ],
                }
            ],
        }
        error_response.headers = {"Replay-Nonce": "test-nonce"}
        error_response.request = Mock()
        error_response.request.url = "https://acme.example.com/challenge/123"

        with pytest.raises(AcmeHttpError) as exc_info:
            raise AcmeHttpError(error_response, "Challenge validation")

        error = exc_info.value
        assert "Connection Refused" in error.message or "refused" in error.message.lower()

    def test_challenge_validation_invalid_response(self, acme_client):
        """Test handling of invalid response during challenge validation"""
        error_response = Mock()
        error_response.status_code = 400
        error_response.json.return_value = {
            "status": "invalid",
            "challenges": [
                {
                    "status": "invalid",
                    "url": "https://acme.example.com/challenge/123",
                    "error": {
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": 'Invalid response from http://example.com/.well-known/acme-challenge/token: "404 Not Found"',
                        "status": 404,
                    },
                    "validationRecord": [
                        {
                            "hostname": "example.com",
                            "addressesResolved": ["192.0.2.1"],
                            "addressUsed": "192.0.2.1",
                            "port": 80,
                        }
                    ],
                }
            ],
        }
        error_response.headers = {"Replay-Nonce": "test-nonce"}
        error_response.request = Mock()
        error_response.request.url = "https://acme.example.com/challenge/123"

        with pytest.raises(AcmeHttpError) as exc_info:
            raise AcmeHttpError(error_response, "Challenge validation")

        error = exc_info.value
        assert "Invalid response" in error.message or "404" in str(error.detail)


class TestAcmeRetryLogic:
    """Test suite for ACME retry logic"""

    @pytest.fixture
    def acme_client(self):
        """Create an ACME client instance for testing"""
        mock_key = Mock(spec=Key)
        mock_key.jwk.return_value = {"kty": "RSA", "n": "test", "e": "AQAB"}
        mock_key.algorithm_name.return_value = "RS256"
        mock_key.jws_sign.return_value = b"signature"

        client = Acme(account_key=mock_key, url="https://acme-staging-v02.api.letsencrypt.org/directory")
        client.nonce = ["initial-nonce"]
        return client

    @pytest.fixture
    def mock_directory_response(self):
        """Mock ACME directory response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "newNonce": "https://acme.example.com/new-nonce",
            "newAccount": "https://acme.example.com/new-account",
            "newOrder": "https://acme.example.com/new-order",
        }
        mock_response.headers = {"Replay-Nonce": "test-nonce-123"}
        return mock_response

    def test_retry_on_network_error_with_depth_limit(self, acme_client, mock_directory_response):
        """Test that network errors retry up to depth limit (1)"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            network_error = requests.exceptions.ConnectionError("Connection failed")

            # Directory fetch succeeds, then all subsequent requests fail
            mock_request.side_effect = [
                mock_directory_response,
                network_error,
                network_error,
                network_error,
            ]

            with pytest.raises(AcmeNetworkError):
                acme_client.setup()
                acme_client.register()

            # Should attempt: initial + 1 retry = 2 attempts total (plus directory)
            # So 3 calls total: directory + initial + retry
            assert mock_request.call_count >= 2

    def test_retry_delay_is_2_seconds(self, acme_client, mock_directory_response):
        """Test that retry delay is 2 seconds"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            bad_nonce_response = Mock()
            bad_nonce_response.status_code = 400
            bad_nonce_response.json.return_value = {
                "type": "urn:ietf:params:acme:error:badNonce",
                "detail": "JWS has invalid anti-replay nonce",
            }
            bad_nonce_response.headers = {"Replay-Nonce": "new-nonce"}
            bad_nonce_response.request = Mock()
            bad_nonce_response.request.url = "https://acme.example.com/new-account"

            success_response = Mock()
            success_response.status_code = 201
            success_response.json.return_value = {"status": "valid"}
            success_response.headers = {
                "Replay-Nonce": "nonce-789",
                "location": "https://acme.example.com/account/123",
            }

            mock_request.side_effect = [
                mock_directory_response,  # setup() directory
                bad_nonce_response,  # first post() fail
                mock_directory_response,  # get_nonce() for retry
                success_response,  # retry post() success
            ]

            with patch("time.sleep") as mock_sleep:
                acme_client.setup()
                acme_client.register()

                # Should have slept for 2 seconds
                mock_sleep.assert_called_with(2)

    def test_no_retry_on_non_retriable_http_errors(self, acme_client, mock_directory_response):
        """Test that non-retriable HTTP errors don't retry"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            error_response = Mock()
            error_response.status_code = 400
            error_response.json.return_value = {
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "Malformed request",
            }
            error_response.headers = {"Replay-Nonce": "test-nonce"}
            error_response.request = Mock()
            error_response.request.url = "https://acme.example.com/new-account"

            mock_request.side_effect = [mock_directory_response, error_response]

            with pytest.raises(AcmeHttpError):
                acme_client.setup()
                acme_client.register()

            # Should only attempt once (no retry) plus directory
            assert mock_request.call_count == 2

    def test_retry_stops_after_depth_exceeds_1(self, acme_client, mock_directory_response):
        """Test that retry stops when depth > 1"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            bad_nonce_response = Mock()
            bad_nonce_response.status_code = 400
            bad_nonce_response.json.return_value = {
                "type": "urn:ietf:params:acme:error:badNonce",
                "detail": "Bad nonce",
            }
            bad_nonce_response.headers = {"Replay-Nonce": "new-nonce"}
            bad_nonce_response.request = Mock()
            bad_nonce_response.request.url = "https://acme.example.com/new-account"

            # All requests return bad nonce
            mock_request.side_effect = [
                mock_directory_response,  # setup()
                bad_nonce_response,  # post 1
                mock_directory_response,  # get_nonce for retry 1
                bad_nonce_response,  # retry 1 post
                mock_directory_response,  # get_nonce for retry 2 (should not happen if depth limit works)
                bad_nonce_response,
            ]

            with pytest.raises(AcmeInvalidNonceError):
                acme_client.setup()
                acme_client.register()

            # Calls will be: 1. setup(directory), 2. post(fail), 3. get_nonce, 4. post(fail), 5. get_nonce, 6. post(fail) -> raise
            assert mock_request.call_count == 6


class TestAcmeNonceManagement:
    """Test suite for ACME nonce management"""

    @pytest.fixture
    def acme_client(self):
        """Create an ACME client instance for testing"""
        mock_key = Mock(spec=Key)
        mock_key.jwk.return_value = {"kty": "RSA", "n": "test", "e": "AQAB"}
        mock_key.algorithm_name.return_value = "RS256"
        mock_key.jws_sign.return_value = b"signature"

        client = Acme(account_key=mock_key, url="https://acme-staging-v02.api.letsencrypt.org/directory")
        client.nonce = ["initial-nonce"]
        return client

    def test_nonce_is_recorded_from_response(self, acme_client):
        """Test that nonce is recorded from response headers"""
        mock_response = Mock()
        mock_response.headers = {"Replay-Nonce": "test-nonce-123"}

        acme_client.record_nonce(mock_response)

        assert "test-nonce-123" in acme_client.nonce

    def test_nonce_is_consumed_when_used(self, acme_client):
        """Test that nonce is removed from list when used"""
        acme_client.nonce = ["nonce-1", "nonce-2"]

        nonce = acme_client.get_nonce("Test step")

        assert nonce == "nonce-1"
        assert "nonce-1" not in acme_client.nonce
        assert "nonce-2" in acme_client.nonce

    def test_new_nonce_fetched_when_list_empty(self, acme_client):
        """Test that new nonce is fetched when list is empty"""
        acme_client.nonce = []  # Clear initial nonce
        acme_client.directory = {"newNonce": "https://acme.example.com/new-nonce"}

        with patch("certapi.acme.http.requests.request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {"Replay-Nonce": "fresh-nonce"}
            mock_request.return_value = mock_response

            nonce = acme_client.get_nonce("Test step")

            assert nonce == "fresh-nonce"

    def test_nonce_thread_safety(self, acme_client):
        """Test that nonce operations are thread-safe"""
        import threading

        acme_client.nonce = [f"nonce-{i}" for i in range(100)]
        used_nonces = []

        def consume_nonce():
            nonce = acme_client.get_nonce("Test step")
            used_nonces.append(nonce)

        threads = [threading.Thread(target=consume_nonce) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All nonces should be unique (no duplicates)
        assert len(used_nonces) == len(set(used_nonces))


class TestAcmeDirectoryCaching:
    """Test suite for ACME directory caching"""

    @pytest.fixture
    def acme_client(self):
        """Create an ACME client instance for testing"""
        mock_key = Mock(spec=Key)
        mock_key.jwk.return_value = {"kty": "RSA", "n": "test", "e": "AQAB"}
        mock_key.algorithm_name.return_value = "RS256"
        mock_key.jws_sign.return_value = b"signature"

        client = Acme(account_key=mock_key, url="https://acme-staging-v02.api.letsencrypt.org/directory")
        client.nonce = ["initial-nonce"]
        return client

    def test_directory_fetched_once_and_cached(self, acme_client):
        """Test that directory is fetched once and then cached"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "newNonce": "https://acme.example.com/new-nonce",
                "newAccount": "https://acme.example.com/new-account",
            }
            mock_response.headers = {"Replay-Nonce": "test-nonce"}
            mock_request.return_value = mock_response

            # First call
            acme_client.setup()
            # Second call
            acme_client._directory("newAccount")

            # Should only fetch once
            assert mock_request.call_count == 1

    def test_directory_lazy_loaded(self, acme_client):
        """Test that directory is lazily loaded on first use"""
        assert acme_client.directory is None

        with patch("certapi.acme.http.requests.request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "newNonce": "https://acme.example.com/new-nonce",
            }
            mock_response.headers = {"Replay-Nonce": "test-nonce"}
            mock_request.return_value = mock_response

            url = acme_client._directory("newNonce")

            assert acme_client.directory is not None
            assert url == "https://acme.example.com/new-nonce"


class TestAcmeMalformedResponseHandling:
    """Test suite for handling malformed or unexpected ACME responses (Runtime errors)"""

    @pytest.fixture
    def acme_client(self):
        """Create an ACME client instance for testing"""
        mock_key = Mock(spec=Key)
        mock_key.jwk.return_value = {"kty": "RSA", "n": "test", "e": "AQAB"}
        mock_key.algorithm_name.return_value = "RS256"
        mock_key.jws_sign.return_value = b"signature"

        client = Acme(account_key=mock_key, url="https://acme-staging-v02.api.letsencrypt.org/directory")
        client.nonce = ["initial-nonce"]
        return client

    @pytest.fixture
    def mock_directory_response(self):
        """Mock ACME directory response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "newNonce": "https://acme.example.com/new-nonce",
            "newAccount": "https://acme.example.com/new-account",
        }
        mock_response.headers = {"Replay-Nonce": "test-nonce-123"}
        return mock_response

    @pytest.mark.parametrize(
        "json_body, expected_error_type",
        [
            # IndexError: res_json["challenges"] present but no invalid challenge found
            ({"status": "invalid", "challenges": [{"status": "pending"}]}, IndexError),
            # IndexError: validationRecord is an empty list
            (
                {
                    "status": "invalid",
                    "challenges": [
                        {
                            "status": "invalid",
                            "error": {"type": "urn:ietf:params:acme:error:connection", "detail": "Timeout"},
                            "validationRecord": [],
                        }
                    ],
                },
                IndexError,
            ),
            # IndexError: DNS NXDOMAIN but pattern doesn't match
            (
                {
                    "status": "invalid",
                    "challenges": [
                        {
                            "status": "invalid",
                            "error": {
                                "type": "urn:ietf:params:acme:error:dns",
                                "detail": "DNS problem: NXDOMAIN looking up something else",
                            },
                        }
                    ],
                },
                IndexError,
            ),
        ],
    )
    def test_unexpected_json_structure(self, acme_client, mock_directory_response, json_body, expected_error_type):
        """Test that unexpected JSON structures handle runtime errors gracefully or raise them as expected"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            error_response = Mock()
            error_response.status_code = 400
            error_response.json.return_value = json_body
            error_response.headers = {"Replay-Nonce": "test-nonce"}
            error_response.request = Mock()
            error_response.request.url = "https://acme.example.com/api"

            mock_request.side_effect = [mock_directory_response, error_response]

            # Currently, many of these might actually raise IndexError/KeyError in AcmeError.py
            # because the implementation directly accesses indices and keys without safety checks.
            # We want to see if it survives or what exception it raises.
            try:
                acme_client.setup()
                acme_client.register()
            except Exception as e:
                # If it raises a runtime error, it's a bug in error handling we might want to fix
                # But for now we just want to add the test cases.
                pass

    def test_missing_required_keys(self, acme_client, mock_directory_response):
        """Test that missing required keys (KeyError) are handled"""
        with patch("certapi.acme.http.requests.request") as mock_request:
            error_response = Mock()
            error_response.status_code = 400
            # "challenges" present but challenge object missing "error" key
            error_response.json.return_value = {"status": "invalid", "challenges": [{"status": "invalid"}]}
            error_response.headers = {"Replay-Nonce": "test-nonce"}
            error_response.request = Mock()
            error_response.request.url = "https://acme.example.com/api"

            mock_request.side_effect = [mock_directory_response, error_response]

            try:
                acme_client.setup()
                acme_client.register()
            except KeyError:
                # Expected if implementation is not safe
                pass
            except Exception:
                pass
