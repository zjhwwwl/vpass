"""Generate Argon2id cross-check vectors with argon2-cffi (independent of libsodium).
Usage: python scripts/gen-argon2-vectors.py > packages/crypto/test/vectors/argon2id.json"""
import json, unicodedata
from argon2.low_level import hash_secret_raw, Type

cases = [
    ("correct horse battery staple", "000102030405060708090a0b0c0d0e0f"),
    ("", "ffffffffffffffffffffffffffffffff"),
    ("密码管理器-🔐-ünïcödé", "a1b2c3d4e5f60718293a4b5c6d7e8f90"),
    ("ｐａｓｓｗｏｒｄ①", "0f0e0d0c0b0a09080706050403020100"),  # fullwidth: NFKC folds to "password1"
]
out = []
for pw, salt in cases:
    norm = unicodedata.normalize("NFKC", pw)
    h = hash_secret_raw(norm.encode("utf-8"), bytes.fromhex(salt), time_cost=3, memory_cost=65536,
                        parallelism=1, hash_len=32, type=Type.ID, version=19)
    out.append({"password": pw, "saltHex": salt, "ops": 3, "memBytes": 67108864, "hashHex": h.hex()})
print(json.dumps(out, ensure_ascii=False, indent=2))
