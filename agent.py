import argparse
import http.server
import socketserver
import sys

def main():
    parser = argparse.ArgumentParser(description="Sub-agent dummy server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, required=True, help="Port to bind to")
    args = parser.parse_args()

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    try:
        with socketserver.TCPServer((args.host, args.port), QuietHandler) as httpd:
            print(f"Agent started at {args.host}:{args.port}")
            httpd.serve_forever()
    except Exception as e:
        print(f"Error starting agent: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
