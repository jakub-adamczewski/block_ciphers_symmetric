from typing import Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from util import byte_xor
from util import ecb_decrypt_bytes
from util import ecb_encrypt_bytes
from util import write_result_to_file


def ecb_encrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r+') as file_in:
        with open(output_path, "w+") as file_out:
            data = '\n'.join(file_in.readlines())
            input_bytes = pad(data.encode(errors='ignore'), AES.block_size)
            blocks_num = int(len(input_bytes) / AES.block_size)
            for i in range(0, blocks_num * AES.block_size, AES.block_size):
                block_bytes = input_bytes[i: i + AES.block_size]
                encrypted = ecb_encrypt_bytes(block_bytes, key)
                file_out.write(encrypted.hex() + '\n')


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
                file_out.write(encrypted.hex() + '\n')


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
                file_out.write(encrypted.hex() + '\n')


def ecb_decrypt(input_path, output_path, key: bytes):
    result = bytearray()
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())
        encrypted_bytes = bytes.fromhex(data)
        blocks_num = int(len(encrypted_bytes) / AES.block_size)
        for i in range(0, blocks_num * AES.block_size, AES.block_size):
            block = encrypted_bytes[i: i + AES.block_size]
            decrypted = ecb_decrypt_bytes(block, key)
            result.extend(decrypted)
        write_result_to_file(result=result, output_path=output_path)


def cbc_decrypt(input_path, output_path, key: bytes, iv: bytes):
    iv_or_last_encrypted_block: bytes = iv
    result = bytearray()
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())
        encrypted_bytes = bytes.fromhex(data)
        blocks_num = int(len(encrypted_bytes) / AES.block_size)
        for i in range(0, blocks_num * AES.block_size, AES.block_size):
            block = encrypted_bytes[i: i + AES.block_size]
            decrypted = ecb_decrypt_bytes(block, key)
            result.extend(byte_xor(iv_or_last_encrypted_block, decrypted))
            iv_or_last_encrypted_block = block
        write_result_to_file(result=result, output_path=output_path)


def pcbc_decrypt(input_path, output_path, key: bytes, iv: bytes):
    iv_or_last_decrypted_block: bytes = iv
    result = bytearray()
    with open(input_path, 'r+') as file_in:
        encrypted_bytes = bytes.fromhex('\n'.join(file_in.readlines()))
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
        write_result_to_file(result=result, output_path=output_path)


def run_algorithm(file_nr: int, algorithm: str, stages: str):
    key = bytes.fromhex('77e557185e757a97fff61e6c5d2b44cc')
    iv_bytes = bytes.fromhex('6dc65237be8e92311de34860f09812f4')
    if algorithm == "ecb":
        if "e" in stages:
            ecb_encrypt(f"files/example_{file_nr}.txt", f"files/{algorithm}/example_{file_nr}_encrypted.txt", key)
        if "d" in stages:
            ecb_decrypt(f"files/{algorithm}/example_{file_nr}_encrypted.txt",
                        f"files/{algorithm}/example_{file_nr}_decrypted.txt", key)
    elif algorithm == "cbc":
        if "e" in stages:
            cbc_encrypt(f"files/example_{file_nr}.txt", f"files/{algorithm}/example_{file_nr}_encrypted.txt", key,
                        iv_bytes)
        if "d" in stages:
            cbc_decrypt(f"files/{algorithm}/example_{file_nr}_encrypted.txt",
                        f"files/{algorithm}/example_{file_nr}_decrypted.txt", key, iv_bytes)
    elif algorithm == "pcbc":
        if "e" in stages:
            pcbc_encrypt(f"files/example_{file_nr}.txt", f"files/{algorithm}/example_{file_nr}_encrypted.txt", key,
                         iv_bytes)
        if "d" in stages:
            pcbc_decrypt(f"files/{algorithm}/example_{file_nr}_encrypted.txt",
                         f"files/{algorithm}/example_{file_nr}_decrypted.txt", key, iv_bytes)
    else:
        raise RuntimeError(f"Algorithm {algorithm} not implemented.")


if __name__ == '__main__':
    key = bytes.fromhex('77e557185e757a97fff61e6c5d2b44cc')
    iv_bytes = bytes.fromhex('6dc65237be8e92311de34860f09812f4')
    # e for encryption, d for decryption
    stages = input("Stages: ")
    run_algorithm(file_nr=1, algorithm="pcbc", stages=stages)
