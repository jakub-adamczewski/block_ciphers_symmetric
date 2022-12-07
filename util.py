from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


def byte_xor(ba1: bytes, ba2: bytes):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


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


def write_result_to_file(result, output_path):
    with open(output_path, "w+") as file_out:
        try:
            file_out.write(unpad(bytes(result), AES.block_size).decode(errors="replace"))
        except ValueError:
            file_out.write(bytes(result).decode(errors="replace"))
