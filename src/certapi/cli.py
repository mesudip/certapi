import argparse
import os
import secrets
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from typing import List, Optional, Tuple
from urllib.parse import unquote

import requests

from certapi import (
    AcmeCertIssuer,
    CertApiException,
    CloudflareChallengeSolver,
    FileSystemKeyStore,
    InMemoryChallengeSolver,
)
from certapi.crypto import certs_from_pem


def is_root() -> bool:
    """Check if running with elevated privileges (cross-platform)."""
    try:
        if os.name == "nt":  # Windows
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix-like (Linux, macOS)
            return os.geteuid() == 0
    except (AttributeError, ImportError, OSError):
        return False


def find_process_on_port(port: int) -> List[str]:
    """Find processes using a specific port (cross-platform)."""
    try:
        if os.name == "nt":  # Windows
            result = subprocess.check_output(["netstat", "-ano"], stderr=subprocess.DEVNULL).decode().strip()
            pids = []
            for line in result.split("\n"):
                if f":{port}" in line and "LISTENING" in line:
                    parts = line.split()
                    if parts:
                        pids.append(parts[-1])
            return pids
        else:  # Unix-like (Linux, macOS)
            result = (
                subprocess.check_output(["lsof", "-i", f":{port}", "-t"], stderr=subprocess.DEVNULL).decode().strip()
            )
            return result.split("\n") if result else []
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _start_http_challenge_server(
    challenge_solver: InMemoryChallengeSolver, port: int = 80
) -> Tuple[TCPServer, threading.Thread]:
    class AcmeChallengeHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            prefix = "/.well-known/acme-challenge/"
            if not self.path.startswith(prefix):
                self.send_error(404)
                return
            token = unquote(self.path[len(prefix) :])
            if not token or "/" in token or "\\" in token:
                self.send_error(400)
                return
            content = challenge_solver.get_challenge(token)
            if not content:
                self.send_error(404)
                return
            if isinstance(content, str):
                content = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, format, *args):
            return

    class ReusableTCPServer(TCPServer):
        allow_reuse_address = True

    server = ReusableTCPServer(("", port), AcmeChallengeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _resolve_cloudflare_api_key() -> Optional[str]:
    return os.environ.get("CLOUDFLARE_API_KEY") or os.environ.get("CLOUDFLARE_API_TOKEN")


def _ensure_port_80_available() -> None:
    if not is_root():
        print("Must be run as root to bind to port 80 for HTTP challenge.")
        sys.exit(1)

    while True:
        pids = find_process_on_port(80)
        if not pids:
            return
        print(f"Process(es) running on port 80: {', '.join(pids)}")
        response = input("Stop the process(es) above, then press Enter to retry (or type 'q' to quit): ")
        if response.strip().lower() == "q":
            sys.exit(1)


def obtain_certificate(domains: List[str], api_key: Optional[str] = None):
    challenge_solver = None
    server = None

    if api_key:
        challenge_solver = CloudflareChallengeSolver(api_key=api_key)
        print("Using Cloudflare DNS challenge.")
    else:
        _ensure_port_80_available()
        challenge_solver = InMemoryChallengeSolver()
        print("Starting HTTP challenge server on port 80...")
        server, _ = _start_http_challenge_server(challenge_solver, port=80)

    keystore_path = "/etc/ssl"
    key_store = FileSystemKeyStore(keystore_path)
    cert_issuer = AcmeCertIssuer.with_keystore(
        key_store,
        challenge_solver,
        account_key_name="acme_account",
    )
    cert_issuer.setup()
    try:
        key, cert = cert_issuer.generate_key_and_cert_for_domains(domains, key_type="rsa")
        key_name = domains[0]
        key_id = key_store.save_key(key, key_name)
        key_store.save_cert(key_id, cert, domains, name=key_name)

        cert_chain = certs_from_pem(cert.encode("utf-8"))
        leaf_cert = cert_chain[0] if cert_chain else None
        expiry = leaf_cert.not_valid_after.isoformat() if leaf_cert else "unknown"

        key_path = os.path.join(key_store.keys_dir, f"{key_name}.key")
        cert_path = os.path.join(key_store.certs_dir, f"{key_name}.crt")
        print(f"\n   Certificate expires at: {expiry}")
        print(f"   Key path: {key_path}")
        print(f"   Cert path: {cert_path}")
    except CertApiException as e:
        print("An error occurred:")
        print(e.json_obj())
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()


def verify_environment(domains: List[str], api_key: Optional[str] = None) -> None:
    if api_key:
        print("[verify] Cloudflare API key detected; DNS-01 challenge available")
        if domains:
            solver = CloudflareChallengeSolver(api_key=api_key)
            unsupported = [domain for domain in domains if not solver.supports_domain(domain)]
            if unsupported:
                print("[verify] Warning: Cloudflare account does not appear to manage:")
                for domain in unsupported:
                    print(f"[verify] - {domain}")
            else:
                print("[verify] Cloudflare account appears to manage the provided domain(s)")
    else:
        print("[verify]  HTTP-01 challenge will be used")
        if not domains:
            print("[verify] No domains provided; skipping HTTP routing check")
            return
        if is_root():
            pids = find_process_on_port(80)
            if pids:
                print(f"[verify] Warning: port 80 is in use by process(es): {', '.join(pids)}")
            else:
                print("[verify] Port 80 is available")
        else:
            print("[verify] Warning: not running as root; port 80 binding will fail")
            return

        _ensure_port_80_available()
        challenge_solver = InMemoryChallengeSolver()
        print("[verify] Starting HTTP challenge server on port 80...")
        server, _ = _start_http_challenge_server(challenge_solver, port=80)
        ok = 0
        failed = 0
        try:
            for domain in domains:
                token = secrets.token_urlsafe(24)
                value = secrets.token_urlsafe(32)
                challenge_solver.save_challenge(token, value, domain)
                url = f"http://{domain}/.well-known/acme-challenge/{token}"
                print(f"[verify] Checking HTTP routing for {domain}...")
                try:
                    response = requests.get(url, allow_redirects=False, timeout=5)
                    if response.status_code == 200 and response.text.strip() == value:
                        ok += 1
                        print(f"[verify] OK: {domain} routes to this server")
                    else:
                        failed += 1
                        print(
                            f"[verify] FAILED: {domain} returned status {response.status_code} "
                            f"with body '{response.text.strip()}'"
                        )
                except requests.RequestException as exc:
                    failed += 1
                    print(f"[verify] FAILED: {domain} request error: {exc}")
                finally:
                    challenge_solver.delete_challenge(token, domain)
        finally:
            server.shutdown()
            server.server_close()
            print(f"\n         Summary: {ok} OK, {failed} FAILED")


def main():
    parser = argparse.ArgumentParser(prog="certapi")
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser("verify", help="Verify certapi installation and environment.")
    verify_parser.add_argument("domains", nargs="*", help="Optional domain(s) to verify.")

    obtain_parser = subparsers.add_parser("obtain", help="Obtain certificate for domains.")
    obtain_parser.add_argument("domains", nargs="+", help="Domain(s) to obtain certificate for.")

    args = parser.parse_args()

    if args.command == "verify":
        api_key = _resolve_cloudflare_api_key()
        verify_environment(args.domains, api_key=api_key)
        sys.exit(0)
    elif args.command == "obtain":
        api_key = _resolve_cloudflare_api_key()
        obtain_certificate(args.domains, api_key=api_key)
    else:
        parser.print_help()
        sys.exit(1)
