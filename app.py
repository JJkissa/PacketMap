#!/usr/bin/env python3
"""Loopback-only PacketMap UI; optional analysis uses the authorized model server."""
import argparse
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body, content_type='application/json'):
        if not isinstance(body, bytes):
            body = json.dumps(body, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def trusted(self):
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        origin = self.headers.get('Origin')
        return self.headers.get('Host') in allowed and (origin is None or origin in {'http://' + host for host in allowed})

    def do_GET(self):
        if not self.trusted():
            return self.respond(403, {'error': 'Only this local app may access the server.'})
        if self.path == '/api/demo':
            if not self.server.analysis_lock.acquire(blocking=False):
                return self.respond(409, {'error': 'An analysis is already running. Please wait.'})
            try:
                from analyzer import analyze
                result = analyze(ROOT / 'examples' / 'demo.pcap')
                return self.respond(200, result)
            except Exception:
                return self.respond(500, {'error': 'Demo unavailable. Regenerate it with examples/make_demo.py.'})
            finally:
                self.server.analysis_lock.release()
        if self.path == '/api/config':
            return self.respond(200, {'token': self.server.token})
        if self.path == '/api/model-settings':
            if not secrets.compare_digest(self.headers.get('X-PacketMap-Token', ''), self.server.token):
                return self.respond(403, {'error': 'Reload the app to access model settings.'})
            return self.respond(200, self.server.model_settings.public())
        assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/model-ui.js': ('model-ui.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
        assets.update({'/analysis-jobs.js': ('analysis-jobs.js', 'text/javascript; charset=utf-8'), '/geo-view.js': ('geo-view.js', 'text/javascript; charset=utf-8'), '/world.json': ('world.json', 'application/json'), '/geo.css': ('geo.css', 'text/css; charset=utf-8')})
        if self.path in assets:
            name, content_type = assets[self.path]
            return self.respond(200, (ROOT / 'static' / name).read_bytes(), content_type)
        self.respond(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.trusted() or not secrets.compare_digest(self.headers.get('X-PacketMap-Token', ''), self.server.token):
            return self.respond(403, {'error': 'Untrusted upload. Reload the app and try again.'})
        if self.path == '/api/geoip':
            return self.do_geoip()
        if self.path == '/api/explain':
            return self.do_explain()
        if self.path == '/api/model-settings':
            return self.do_model_settings()
        if self.path != '/api/analyze':
            return self.respond(404, {'error': 'Not found'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.respond(400, {'error': 'Invalid upload length.'})
        if size <= 0 or size > 256 * 1024 * 1024:
            return self.respond(413, {'error': 'Choose a non-empty capture up to 256 MiB. Split larger captures with Wireshark or editcap.'})
        if not self.server.analysis_lock.acquire(blocking=False):
            return self.respond(409, {'error': 'An analysis is already running. Please wait.'})
        try:
            import tempfile
            self.connection.settimeout(120)
            with tempfile.TemporaryDirectory(prefix='packetmap-') as folder:
                path = Path(folder) / 'capture.pcap'
                with path.open('wb') as stream:
                    remaining = size
                    while remaining:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError('Upload ended before the file was complete.')
                        stream.write(chunk)
                        remaining -= len(chunk)
                with path.open('rb') as stream:
                    magic = stream.read(4)
                if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
                    raise ValueError('Not a PCAP or PCAPNG capture. Export a capture from Wireshark and try again.')
                from analyzer import analyze
                result = analyze(path)
            self.respond(200, result)
        except (ValueError, OSError, EOFError) as exc:
            self.respond(400, {'error': str(exc)[:400]})
        except Exception:
            self.respond(400, {'error': 'The capture could not be decoded. It may be damaged or use an unsupported format.'})
        finally:
            self.server.analysis_lock.release()

    def do_model_settings(self):
        if not self.server.explanation_lock.acquire(blocking=False):
            return self.respond(409, {'error': 'A model request is active. Wait until it finishes before saving settings.'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384:
                return self.respond(413, {'error': 'Settings must be at most 16 KiB.'})
            self.connection.settimeout(15)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Incomplete settings request.')
            result = self.server.model_settings.save(json.loads(raw))
            self.server.legacy_model_default = False
            return self.respond(200, result)
        except (ValueError, TypeError):
            return self.respond(400, {'error': 'Invalid settings. Use an origin URL without credentials, path, query or fragment; non-loopback requires HTTPS and remote authorization. Check model, API mode and key.'})
        except OSError:
            return self.respond(500, {'error': 'Could not persist private model settings.'})
        finally:
            self.server.explanation_lock.release()

    def do_geoip(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 1024 * 1024:
                return self.respond(413, {'error': 'GeoIP request exceeds 1 MiB.'})
            self.connection.settimeout(15)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Incomplete GeoIP request.')
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError('Expected GeoIP address list.')
            from geoip_local import locate
            return self.respond(200, locate(payload.get('addresses')))
        except (ValueError, TypeError, OSError) as exc:
            return self.respond(400, {'error': str(exc)[:200]})

    def do_explain(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.respond(400, {'error': 'Invalid explanation length.'})
        if not 0 < size <= 32768:
            return self.respond(413, {'error': 'Explanation evidence must be at most 32 KiB.'})
        if not self.server.explanation_lock.acquire(blocking=False):
            return self.respond(409, {'error': 'A model explanation is still running. Wait before trying again.'})
        try:
            connection = self.server.model_settings.snapshot()
            revision = self.headers.get('X-PacketMap-Model-Revision')
            if revision != connection['revision'] and (revision is not None or not self.server.legacy_model_default):
                return self.respond(409, {'error': 'Model settings changed. Batch stopped; review the connection and start a new analysis.'})
            self.connection.settimeout(15)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Incomplete explanation request.')
            from llm_client import explain
            result = explain(json.loads(raw), settings=connection) if revision is not None else explain(json.loads(raw))
            status = 200
        except (ValueError, OSError) as exc:
            status, result = 400, {'error': str(exc)[:400]}
        except Exception:
            status, result = 400, {'error': 'Model explanation failed. Capture analysis is still available.'}
        finally:
            self.server.explanation_lock.release()
        try:
            self.respond(status, result)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Browser cancelled; do not retry writing the response.

    def log_message(self, fmt, *args):
        # Do not print user filenames or packet contents to logs.
        pass


def create_server(port=8765, settings_path=None):
    from model_settings import SettingsStore
    settings = SettingsStore(settings_path)
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.model_settings = settings
    server.legacy_model_default = not settings.path.exists()
    server.token = secrets.token_urlsafe(32)
    server.analysis_lock = threading.Lock()
    server.explanation_lock = threading.Lock()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765, help='Local port; 0 chooses a free port')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    try:
        server = create_server(args.port)
    except OSError as exc:
        parser.exit(1, f'Cannot start local server: {exc}. Try --port 0.\n')
    url = f'http://127.0.0.1:{server.server_port}'
    print(f'PacketMap: {url}\nCapture decoding stays local; optional model analysis uses your configured backend. Press Ctrl+C to stop.', flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
