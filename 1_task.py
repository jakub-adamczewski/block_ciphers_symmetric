import json
from base64 import b64encode, b64decode
from time import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def measure_time(func):
    def wrapper(*args, **kwargs):
        start = time()
        func(*args, **kwargs)
        end = time()
        print('Time: %.6f' % (end - start))

    return wrapper


@measure_time
def ecb_encrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r+') as file_in:
        data = ''.join(file_in.readlines())
        data_bytes = data.encode(errors='ignore')

        cipher = AES.new(key, AES.MODE_ECB)

        ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))

    with open(output_path, "wb") as file_out:
        file_out.write(ct_bytes)


@measure_time
def ecb_decrypt(input_path, output_path, key: bytes):
    with open(input_path, 'rb') as file_in:
        data_bytes = file_in.read()

        cipher = AES.new(key, AES.MODE_ECB)

        ct_bytes = unpad(cipher.decrypt(data_bytes), AES.block_size)

    with open(output_path, "w+") as file_out:
        file_out.write(ct_bytes.decode())


@measure_time
def cbc_encrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())

    data_bytes = data.encode(errors='ignore')

    cipher = AES.new(key, AES.MODE_CBC)

    ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})

    with open(output_path, "w+") as file_out:
        file_out.write(result)


@measure_time
def cbc_decrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r') as file_in:
        json_input = file_in.read()

    b64 = json.loads(json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])

    cipher = AES.new(key, AES.MODE_CBC, iv)

    ct_bytes = unpad(cipher.decrypt(ct), AES.block_size)

    with open(output_path, "w+") as file_out:
        file_out.write(ct_bytes.decode())


@measure_time
def ctr_encrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())
    data_bytes = data.encode(errors='ignore')

    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(data_bytes)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'nonce': nonce, 'ciphertext': ct})

    with open(output_path, "w+") as file_out:
        file_out.write(result)


@measure_time
def ctr_decrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r') as file_in:
        json_input = file_in.read()

    b64 = json.loads(json_input)
    nonce = b64decode(b64['nonce'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)

    with open(output_path, "w+") as file_out:
        file_out.write(pt.decode())


@measure_time
def cfb_encrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())
    data_bytes = data.encode(errors='ignore')

    cipher = AES.new(key, AES.MODE_CFB)
    ct_bytes = cipher.encrypt(data_bytes)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})

    with open(output_path, "w+") as file_out:
        file_out.write(result)


@measure_time
def cfb_decrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r') as file_in:
        json_input = file_in.read()

    b64 = json.loads(json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)

    with open(output_path, "w+") as file_out:
        file_out.write(pt.decode())


@measure_time
def ofb_encrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())
    data_bytes = data.encode(errors='ignore')

    cipher = AES.new(key, AES.MODE_OFB)
    ct_bytes = cipher.encrypt(data_bytes)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})

    with open(output_path, "w+") as file_out:
        file_out.write(result)


@measure_time
def ofb_decrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r') as file_in:
        json_input = file_in.read()

    b64 = json.loads(json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    pt = cipher.decrypt(ct)

    with open(output_path, "w+") as file_out:
        file_out.write(pt.decode())


@measure_time
def siv_encrypt(input_path, output_path,
                key: bytes = get_random_bytes(AES.block_size * 2),
                nonce: bytes = get_random_bytes(AES.block_size),
                header: bytes = b'header'
                ):
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())
        data_bytes = data.encode(errors='ignore')
        cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        json_v = [b64encode(x).decode('utf-8') for x in (nonce, header, ciphertext, tag)]
        result = json.dumps(dict(zip(json_k, json_v)))
        with open(output_path, "w+") as file_out:
            file_out.write(result)


@measure_time
def siv_decrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r') as file_in:
        json_input = file_in.read()
        b64 = json.loads(json_input)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_SIV, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        with open(output_path, "w+") as file_out:
            file_out.write(plaintext.decode())


@measure_time
def gcm_encrypt(input_path, output_path,
                key: bytes = get_random_bytes(AES.block_size),
                header: bytes = b'header'
                ):
    with open(input_path, 'r+') as file_in:
        data = '\n'.join(file_in.readlines())
        data_bytes = data.encode(errors='ignore')
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag]]
        result = json.dumps(dict(zip(json_k, json_v)))
        with open(output_path, "w+") as file_out:
            file_out.write(result)


@measure_time
def gcm_decrypt(input_path, output_path, key: bytes):
    with open(input_path, 'r') as file_in:
        json_input = file_in.read()
        b64 = json.loads(json_input)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        with open(output_path, "w+") as file_out:
            file_out.write(plaintext.decode())


if __name__ == '__main__':
    key = get_random_bytes(16)

    for i in range(1, 4):
        for mode, (encrypt, decrypt) in {
            'ecb': (ecb_encrypt, ecb_decrypt),
            'cbc': (cbc_encrypt, cbc_decrypt),
            'cfb': (cfb_encrypt, cfb_decrypt),
            'ofb': (ofb_encrypt, ofb_decrypt),
            'ctr': (ctr_encrypt, ctr_decrypt),
            'gcm': (gcm_encrypt, gcm_decrypt)
        }.items():
            print(f'{mode.upper()} encrypt example_{i}.txt. ', end='')

            encrypt(f'files/example_{i}.txt',
                    f'files/{mode}_example_{i}_encrypted.txt',
                    key)

            print(f'{mode.upper()} decrypt example_{i}.txt. ', end='')

            decrypt(f'files/{mode}_example_{i}_encrypted.txt',
                    f'files/{mode}_example_{i}_decrypted.txt',
                    key)
        print('# ' * 50)

    key = get_random_bytes(AES.block_size * 2)

    for i in range(1, 4):
        for mode, (encrypt, decrypt) in {
            'siv': (siv_encrypt, siv_decrypt)
        }.items():
            print(f'{mode.upper()} encrypt example_{i}.txt. ', end='')

            encrypt(f'files/example_{i}.txt',
                    f'files/{mode}_example_{i}_encrypted.txt',
                    key)

            print(f'{mode.upper()} decrypt example_{i}.txt. ', end='')

            decrypt(f'files/{mode}_example_{i}_encrypted.txt',
                    f'files/{mode}_example_{i}_decrypted.txt',
                    key)
        print('# ' * 50)
