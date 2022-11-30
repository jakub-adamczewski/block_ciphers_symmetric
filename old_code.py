
@measure_time
def encrypt(input_path, output_path, key: bytes, mode: AES):
    cipher = AES.new(key, mode)

    with open(input_path, 'r+') as file_in:
        with open(output_path, "wb") as file_out:
            with open('bin_' + output_path, "w") as binary_file_out:
                last = False
                while not last:
                    data = file_in.read(16)
                    if len(data) < 16:
                        last = True
                        missing = 16-len(data)
                        data += chr(missing) * missing
                    data_bytes = data.encode(errors='ignore')

                    encrypted_bytes = cipher.encrypt(data_bytes)
                    file_out.write(encrypted_bytes)

                    bits = BitArray(bytes=encrypted_bytes).bin
                    binary_file_out.write(bits[2:])


@measure_time
def decrypt(input_path, output_path, key: bytes, mode: AES):
    cipher = AES.new(key, mode)

    with open(input_path, 'rb') as file_in:
        with open(output_path, "wb") as file_out:
            while data_bytes := file_in.read(16):
                decrypted_bytes = cipher.decrypt(data_bytes)

                for i in range(1, 17):
                    x = -i
                    if decrypted_bytes[x:] == (chr(i) * i).encode():
                        decrypted_bytes = decrypted_bytes[:16-i]
                        continue

                # data = decrypted_bytes.decode(errors='ignore')
                file_out.write(decrypted_bytes)