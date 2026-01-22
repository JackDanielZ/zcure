#!/usr/bin/env python3
import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from common_app import *

def main():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if KEYS_FILE.exists():
        with KEYS_FILE.open() as f:
            keys = json.load(f)
    else:
        keys = {}
    keys["local"] = {}

    # Generate P-384 key pair
    priv = ec.generate_private_key(ec.SECP384R1(), default_backend())
    pub = priv.public_key()

    # Private scalar (384 bits → 96 hex chars)
    priv_val = priv.private_numbers().private_value
    keys["local"]["p"] = f"{priv_val:096x}"

    # Public X/Y coordinates (384 bits each)
    pub_nums = pub.public_numbers()
    keys["local"]["x"] = f"{pub_nums.x:096x}"
    keys["local"]["y"] = f"{pub_nums.y:096x}"

    # Write local keys
    with KEYS_FILE.open("w") as f:
        json.dump(keys, f, indent=2)

    print(f"Generated P‑384 keys in {KEYS_FILE}")

if __name__ == "__main__":
    main()

