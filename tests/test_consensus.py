"""Tests for chain.consensus — PoW mining and difficulty adjustment."""

from chain.block import Block
from chain.consensus import (
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    TARGET_BLOCK_TIME_SECONDS,
    adjust_difficulty,
    mine_block,
    validate_proof,
)


def _blank_block(index: int = 1, prev: str = "0" * 64) -> Block:
    return Block(index=index, transactions=[], previous_hash=prev, timestamp=float(index))


class TestMineBlock:
    def test_hash_starts_with_difficulty_zeros(self):
        b = _blank_block()
        mine_block(b, difficulty=1)
        assert b.hash.startswith("0")

    def test_hash_matches_compute_hash_after_mining(self):
        b = _blank_block()
        mine_block(b, difficulty=1)
        assert b.hash == b.compute_hash()

    def test_returns_same_block_object(self):
        b = _blank_block()
        result = mine_block(b, difficulty=1)
        assert result is b

    def test_nonce_is_non_negative(self):
        b = _blank_block()
        mine_block(b, difficulty=1)
        assert b.nonce >= 0

    def test_difficulty_2(self):
        b = _blank_block()
        mine_block(b, difficulty=2)
        assert b.hash.startswith("00")


class TestValidateProof:
    def test_mined_block_validates(self):
        b = _blank_block()
        mine_block(b, difficulty=1)
        assert validate_proof(b, difficulty=1) is True

    def test_tampered_hash_fails(self):
        b = _blank_block()
        mine_block(b, difficulty=1)
        b.hash = "0" + "f" * 63  # starts with 0 but hash doesn't match payload
        assert validate_proof(b, difficulty=1) is False

    def test_wrong_difficulty_fails(self):
        b = _blank_block()
        mine_block(b, difficulty=1)
        # Difficulty=2 requires "00" prefix; difficulty=1 block may not have it
        if not b.hash.startswith("00"):
            assert validate_proof(b, difficulty=2) is False

    def test_unmined_block_fails(self):
        b = _blank_block()
        # Default hash almost certainly won't start with "000"
        assert validate_proof(b, difficulty=3) is False


class TestAdjustDifficulty:
    def _make_chain(self, n: int, elapsed_seconds: float) -> list[Block]:
        """Build n+1 blocks where the last n span elapsed_seconds total."""
        chain = [Block(index=0, transactions=[], previous_hash="0" * 64, timestamp=0.0)]
        step = elapsed_seconds / n if n > 0 else 1.0
        for i in range(1, n + 1):
            chain.append(
                Block(index=i, transactions=[], previous_hash=chain[-1].hash, timestamp=float(i) * step)
            )
        return chain

    def test_too_short_chain_unchanged(self):
        chain = self._make_chain(DIFFICULTY_ADJUSTMENT_INTERVAL - 1, 100)
        assert adjust_difficulty(chain, 3) == 3

    def test_fast_blocks_increase_difficulty(self):
        # Blocks came every 0.1s — way faster than 10s target
        chain = self._make_chain(DIFFICULTY_ADJUSTMENT_INTERVAL, elapsed_seconds=1.0)
        new_d = adjust_difficulty(chain, 3)
        assert new_d > 3

    def test_slow_blocks_decrease_difficulty(self):
        # Blocks came every 1000s — way slower than 10s target
        chain = self._make_chain(DIFFICULTY_ADJUSTMENT_INTERVAL, elapsed_seconds=10_000.0)
        new_d = adjust_difficulty(chain, 3)
        assert new_d < 3

    def test_difficulty_never_drops_below_one(self):
        chain = self._make_chain(DIFFICULTY_ADJUSTMENT_INTERVAL, elapsed_seconds=10_000.0)
        assert adjust_difficulty(chain, 1) >= 1

    def test_on_target_unchanged(self):
        expected = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME_SECONDS
        chain = self._make_chain(DIFFICULTY_ADJUSTMENT_INTERVAL, elapsed_seconds=expected)
        assert adjust_difficulty(chain, 3) == 3
