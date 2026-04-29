"""Tamper demonstration endpoint.

This endpoint intentionally corrupts a block's transaction data WITHOUT
recomputing its hash.  The stored hash then no longer matches the block's
content, breaking chain validity.

It is intended purely as an educational demonstration of why the hash
chain makes blockchains tamper-evident.

Endpoints
---------
POST /api/tamper/<index>
    Tamper with block <index>.

POST /api/chain/restore
    Reset the node to a fresh state (undo all tampering).
"""

from flask import Blueprint, jsonify, request

from api import state as state_module
from api.state import get_node

tamper_bp = Blueprint("tamper", __name__)


@tamper_bp.route("/tamper/<int:index>", methods=["POST"])
def tamper_block(index: int):
    """Inject a fake transaction into *block[index]* without updating its hash.

    This breaks ``is_valid_chain()`` because the stored hash no longer
    matches the block's actual content.

    Args:
        index: Block index to tamper (genesis block 0 is disallowed).

    Body (JSON, optional)::

        {"tamper_value": "HACKED"}

    Returns:
        200 with before/after info and chain validity status.
        400 if the index is invalid.
    """
    node = get_node()
    bc = node.blockchain

    if index <= 0 or index >= bc.height():
        return (
            jsonify(
                {
                    "error": (
                        f"Index {index} is out of range. "
                        "Genesis block (0) cannot be tampered. "
                        f"Valid range: 1 – {bc.height() - 1}."
                    )
                }
            ),
            400,
        )

    data = request.get_json(force=True, silent=True) or {}
    tamper_value = str(data.get("tamper_value", "TAMPERED_DATA"))

    block = bc.chain[index]
    original_hash = block.hash
    original_tx_count = len(block.transactions)

    # Mutate WITHOUT recomputing hash — this is the attack
    block.transactions.append(
        {"sender": "ATTACKER", "receiver": "ATTACKER", "amount": 999_999, "note": tamper_value}
    )

    return jsonify(
        {
            "message": f"Block #{index} has been tampered. Chain is now INVALID.",
            "block_index": index,
            "original_tx_count": original_tx_count,
            "new_tx_count": len(block.transactions),
            "original_hash": original_hash,
            "recomputed_hash": block.compute_hash(),
            "stored_hash": block.hash,
            "hash_mismatch": block.hash != block.compute_hash(),
            "chain_valid": bc.is_valid_chain(),
        }
    )


@tamper_bp.route("/chain/restore", methods=["POST"])
def restore_chain():
    """Reset the node to a clean genesis-only state.

    Use this to undo tampering during a demonstration.

    Returns:
        200 with a confirmation message.
    """
    state_module.reset_node()
    node = get_node()  # lazy-creates a fresh node
    return jsonify(
        {
            "message": "Chain restored to clean state",
            "height": node.blockchain.height(),
            "chain_valid": node.blockchain.is_valid_chain(),
        }
    )
