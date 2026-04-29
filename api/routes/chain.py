"""Chain-level endpoints — stats, validation, and mining."""

import time

from flask import Blueprint, jsonify, request

from api.state import get_node

chain_bp = Blueprint("chain", __name__)

_DEFAULT_MINER = "0x0000000000000000000000000000000000000001"


@chain_bp.route("/chain/stats", methods=["GET"])
def chain_stats():
    """Return live chain statistics.

    Response::

        {
            "height": 4,
            "total_transactions": 12,
            "difficulty": 3,
            "pending_transactions": 2,
            "last_hash": "000abc...",
            "last_block_index": 3,
            "is_valid": true
        }
    """
    node = get_node()
    bc = node.blockchain
    last = bc.last_block()
    return jsonify(
        {
            "height": bc.height(),
            "total_transactions": bc.total_transactions(),
            "difficulty": node.difficulty,
            "pending_transactions": bc.mempool.pending_count(),
            "last_hash": last.hash,
            "last_block_index": last.index,
            "is_valid": bc.is_valid_chain(),
        }
    )


@chain_bp.route("/chain/validate", methods=["GET"])
def validate_chain():
    """Return whether the current chain is structurally valid.

    Response::

        {"valid": true, "height": 4}
    """
    node = get_node()
    valid = node.blockchain.is_valid_chain()
    return jsonify({"valid": valid, "height": node.blockchain.height()})


@chain_bp.route("/mine", methods=["POST"])
def mine():
    """Mine pending transactions into a new block.

    Body (JSON, optional)::

        {"miner_address": "0x..."}

    Returns:
        201 with the mined block dict on success.
        500 if mining fails.
    """
    data = request.get_json(force=True, silent=True) or {}
    miner_address = str(data.get("miner_address", _DEFAULT_MINER))

    node = get_node()
    start = time.time()
    block = node.mine_pending_transactions(miner_address)
    elapsed = round(time.time() - start, 3)

    if block is None:
        return jsonify({"error": "Mining failed — block could not be added to chain"}), 500

    return (
        jsonify(
            {
                "message": "Block mined successfully",
                "block": block.to_dict(),
                "time_seconds": elapsed,
                "new_difficulty": node.difficulty,
            }
        ),
        201,
    )
