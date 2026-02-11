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

from certapi import AcmeCertIssuer, CertApiException, CloudflareChallengeSolver, InMemoryChallengeSolver, Key


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def find_process_on_port(port: int) -> List[str]:
    try:
        result = subprocess.check_output(["lsof", "-i", f":{port}", "-t"]).decode().strip()
        return result.split("\n") if result else []
    except subprocess.CalledProcessError:
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

    cert_issuer = AcmeCertIssuer(Key.generate("ecdsa"), challenge_solver)
    cert_issuer.setup()
    try:
        key, cert = cert_issuer.generate_key_and_cert_for_domains(domains)
        print("------ Private Key -----")
        print(key.to_pem().decode("utf-8"))
        print("------- Certificate ------")
        print(cert)
    except CertApiException as e:
        print("An error occurred:")
        print(e.json_obj())
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()


def verify_environment(domains: List[str], api_key: Optional[str] = None) -> None:
    print("certapi is installed and CLI is working.")
    if api_key:
        print("Cloudflare API key detected. DNS challenge is available.")
        if domains:
            solver = CloudflareChallengeSolver(api_key=api_key)
            unsupported = [domain for domain in domains if not solver.supports_domain(domain)]
            if unsupported:
                print("Warning: Cloudflare account does not appear to manage:")
                for domain in unsupported:
                    print(f"- {domain}")
            else:
                print("Cloudflare account appears to manage the provided domain(s).")
    else:
        print("Cloudflare API key not detected. HTTP challenge will be used.")
        if not domains:
            print("No domains provided. Skipping HTTP routing check.")
            return
        if is_root():
            pids = find_process_on_port(80)
            if pids:
                print(f"Warning: port 80 is in use by process(es): {', '.join(pids)}")
            else:
                print("Port 80 is available.")
        else:
            print("Warning: not running as root, port 80 binding will fail.")
            return

        _ensure_port_80_available()
        challenge_solver = InMemoryChallengeSolver()
        print("Starting HTTP challenge server on port 80...")
        server, _ = _start_http_challenge_server(challenge_solver, port=80)
        try:
            for domain in domains:
                token = secrets.token_urlsafe(24)
                value = secrets.token_urlsafe(32)
                challenge_solver.save_challenge(token, value, domain)
                url = f"http://{domain}/.well-known/acme-challenge/{token}"
                print(f"Verifying HTTP routing for {domain}...")
                try:
                    response = requests.get(url, allow_redirects=False, timeout=5)
                    if response.status_code == 200 and response.text.strip() == value:
                        print(f"OK: {domain} routes to this server.")
                    else:
                        print(
                            f"Failed: {domain} returned status {response.status_code} "
                            f"with body '{response.text.strip()}'"
                        )
                except requests.RequestException as exc:
                    print(f"Failed: {domain} request error: {exc}")
                finally:
                    challenge_solver.delete_challenge(token, domain)
        finally:
            server.shutdown()
            server.server_close()


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
