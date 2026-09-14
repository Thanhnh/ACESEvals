"""Deterministic RNG patching for reproducible credential generation."""
import random
import secrets
import uuid


def patch_rng(seed_int: int) -> None:
    """Patch secrets/uuid/random to use a deterministic PRNG."""
    rng = random.Random(seed_int)

    def _seeded_token_bytes(n=32):
        return bytes(rng.getrandbits(8) for _ in range(n))

    def _seeded_token_hex(n=32):
        return _seeded_token_bytes(n).hex()

    def _seeded_choice(seq):
        return rng.choice(seq)

    secrets.token_bytes = _seeded_token_bytes
    secrets.token_hex = _seeded_token_hex
    secrets.choice = _seeded_choice

    def _seeded_uuid4():
        return uuid.UUID(int=rng.getrandbits(128), version=4)
    uuid.uuid4 = _seeded_uuid4

    random.seed(seed_int)
