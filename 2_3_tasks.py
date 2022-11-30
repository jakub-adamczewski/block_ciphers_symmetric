import chunk
import json
import sys
from base64 import b64encode, b64decode
from time import time
from typing import Optional

from util import byte_xor

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def ecb_encrypt_bytes(input_bytes: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(input_bytes)


def ecb_decrypt_bytes(input_bytes: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(input_bytes)


def cbc_encrypt_lib(input_path, output_path, key: bytes):
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())

    data_bytes = data.encode(errors='ignore')
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))

    with open(output_path, "w+") as file_out:
        file_out.write(ct_bytes.hex())
    return bytes(cipher.iv)


def cbc_encrypt(input_path, output_path, key: bytes, iv: bytes):
    iv_or_last_encrypted_block: bytes = iv
    with open(input_path, 'r+') as file_in:
        with open(output_path, "w+") as file_out:
            data = '\n'.join(file_in.readlines())
            input_bytes = pad(data.encode(errors='ignore'), AES.block_size)
            blocks_num = int(len(input_bytes) / AES.block_size)
            for i in range(0, blocks_num * AES.block_size, AES.block_size):
                block_bytes = input_bytes[i: i + AES.block_size]
                encrypted = ecb_encrypt_bytes(byte_xor(iv_or_last_encrypted_block, block_bytes), key)
                iv_or_last_encrypted_block = encrypted
                file_out.write(encrypted.hex())


def pcbc_encrypt(input_path, output_path, key: bytes, iv: bytes):
    iv_or_previous_encrypted_block: bytes = iv
    with open(input_path, 'r+') as file_in:
        with open(output_path, "w+") as file_out:
            data = '\n'.join(file_in.readlines())
            input_bytes = pad(data.encode(errors='ignore'), AES.block_size)
            previous_plaintext_block: Optional[bytes] = None
            blocks_num = int(len(input_bytes) / AES.block_size)
            for i in range(0, blocks_num * AES.block_size, AES.block_size):
                block_bytes = input_bytes[i: i + AES.block_size]
                first_xor_result = block_bytes
                if previous_plaintext_block is not None:
                    first_xor_result = byte_xor(previous_plaintext_block, block_bytes)
                second_xor_result = byte_xor(first_xor_result, iv_or_previous_encrypted_block)
                encrypted = ecb_encrypt_bytes(second_xor_result, key)
                iv_or_previous_encrypted_block = encrypted
                previous_plaintext_block = block_bytes
                file_out.write(encrypted.hex())


def cbc_decrypt(input_path, output_path, key: bytes, iv: bytes):
    iv_or_last_encrypted_block: bytes = iv
    result = bytearray()
    with open(input_path, 'r+') as file_in:
        data = ''.join(file_in.readlines())
        encrypted_bytes = bytes.fromhex(data)
        blocks_num = int(len(encrypted_bytes) / AES.block_size)
        for i in range(0, blocks_num * AES.block_size, AES.block_size):
            block = encrypted_bytes[i: i + AES.block_size]
            decrypted = ecb_decrypt_bytes(block, key)
            result.extend(byte_xor(iv_or_last_encrypted_block, decrypted))
            iv_or_last_encrypted_block = block
        with open(output_path, "w+") as file_out:
            file_out.write(unpad(bytes(result), AES.block_size).decode())


def pcbc_decrypt(input_path, output_path, key: bytes, iv: bytes):
    iv_or_last_decrypted_block: bytes = iv
    result = bytearray()
    with open(input_path, 'r+') as file_in:
        encrypted_bytes = bytes.fromhex(''.join(file_in.readlines()))
        previous_encrypted_block: Optional[bytes] = None
        blocks_num = int(len(encrypted_bytes) / AES.block_size)
        for i in range(0, blocks_num * AES.block_size, AES.block_size):
            block = encrypted_bytes[i: i + AES.block_size]
            decrypted = ecb_decrypt_bytes(block, key)
            first_decrypted_xor = decrypted
            if previous_encrypted_block is not None:
                first_decrypted_xor = byte_xor(previous_encrypted_block, decrypted)
            second_decrypted_xor = byte_xor(iv_or_last_decrypted_block, first_decrypted_xor)
            result.extend(second_decrypted_xor)
            iv_or_last_decrypted_block = second_decrypted_xor
            previous_encrypted_block = block
        with open(output_path, "w+") as file_out:
            file_out.write(unpad(bytes(result), AES.block_size).decode())


def test(msg: str = "Hello big world"):
    msg_bytes = pad(str.encode(msg), AES.block_size)
    key = get_random_bytes(16)
    encrypted = ecb_encrypt_bytes(msg_bytes, key)
    print(encrypted)
    decrypted = unpad(ecb_decrypt_bytes(encrypted, key), AES.block_size).decode()
    print(decrypted)


if __name__ == '__main__':
    key = bytes.fromhex('77e557185e757a97fff61e6c5d2b44cc')
    iv_bytes = bytes.fromhex('6dc65237be8e92311de34860f09812f4')
    # iv_bytes = cbc_encrypt_lib("files/example_1.txt", "files/example_1_lib.txt", key)
    # cbc_encrypt("files/example_1.txt", "files/example_1_cbc_our.txt", key, iv_bytes)
    # cbc_decrypt("files/example_1_cbc_our.txt", "files/example_1_cbc_our_decr.txt", key, iv_bytes)
    pcbc_encrypt("files/example_1.txt", "files/example_1_pcbc_our.txt", key, iv_bytes)
    pcbc_decrypt("files/example_1_pcbc_our.txt", "files/example_1_pcbc_our_decr.txt", key, iv_bytes)
