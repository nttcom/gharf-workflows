import pefile
import os
import sys

def inject_marker(path: str, marker: bytes):
    norm_path = os.path.normpath(path)
    print(f"[DEBUG] Normalized path: {norm_path}")

    if not os.path.isfile(norm_path):
        print(f"[ERROR] File not found: {norm_path}")
        sys.exit(1)

    with open(norm_path, 'rb') as f:
        binary = bytearray(f.read())

    pe = pefile.PE(data=binary)

    dos_end = pe.DOS_HEADER.e_lfanew
    marker_pos = max(0, dos_end - len(marker))
    binary[marker_pos:marker_pos + len(marker)] = marker

    with open(norm_path, 'wb') as f:
        f.write(binary)

if __name__ == "__main__":
    input_path = os.environ.get("INPUT_BINARY_PATH")
    marker = b'IOC-GHARF'

    if not input_path:
        print("Error: INPUT_BINARY_PATH must be set")
        sys.exit(1)

    inject_marker(input_path, marker)