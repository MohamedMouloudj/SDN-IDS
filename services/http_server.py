from http.server import HTTPServer, SimpleHTTPRequestHandler

server = HTTPServer(("0.0.0.0",80), SimpleHTTPRequestHandler)
print('HTTP server running on port 80')
server.serve_forever()