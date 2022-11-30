def byte_xor(ba1: bytes, ba2: bytes):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
