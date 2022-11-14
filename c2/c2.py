import socketserver

class C2Handler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)
        
    
    def handle(self) -> None:
        self.data = self.request.recv(22)
        print(self.data[:6].hex())
        print(self.data[6:].hex())

with socketserver.TCPServer(("0.0.0.0", 1337), C2Handler) as server:
    server.serve_forever()

