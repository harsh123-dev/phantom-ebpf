"""
services/ebpf-agent/domain/markov/serializer.py

Serialize and deserialize a MarkovModel to/from JSON.

Format:
{
  "schema_version": "v1",
  "k_star": int,
  "m": int,
  "N": int,
  "bic_score": float,
  "training_sequences_count": int,
  "sigma": [token_as_list, ...],
  "retained_contexts": [[token_as_list, ...], ...],
  "transition": {
      "<context_key>": {"<token_key>": float, ...},
      ...
  },
  "epsilon": {"<context_key>": float, ...}
}

Token serialization: a Token is a 4-tuple of strings; serialized as a
JSON 4-element array. Context serialization: a Context is a tuple of Tokens;
serialized as a JSON array of 4-element arrays.

Context keys in "transition" and "epsilon" objects use a stable string
encoding: "|".join(";".join(t) for t in context). The empty context
is encoded as the empty string "".
"""

from __future__ import annotations

import json
from typing import Any

from domain.markov.chain import (
    Context,
    MarkovModel,
    Token,
)

# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def _encode_token(t: Token) -> list[str]:
    """Serialize a Token to a 4-element list.

    Args:
        t: A 4-tuple (event_type, operation_class, resource_class, privilege_class).

    Returns:
        A 4-element list of strings.
    """
    return list(t)


def _decode_token(lst: list[str]) -> Token:
    """Deserialize a 4-element list into a Token.

    Args:
        lst: A 4-element list of strings.

    Returns:
        A Token (4-tuple of strings).

    Raises:
        ValueError: If the list does not have exactly 4 elements.
    """
    if len(lst) != 4:
        raise ValueError(f"Expected 4-element token, got {len(lst)}: {lst}")
    return (lst[0], lst[1], lst[2], lst[3])


def _encode_context(ctx: Context) -> list[list[str]]:
    """Serialize a Context (tuple of Tokens) to a list of 4-element lists.

    Args:
        ctx: A context tuple.

    Returns:
        A list of 4-element string lists.
    """
    return [_encode_token(t) for t in ctx]


def _decode_context(lst: list[list[str]]) -> Context:
    """Deserialize a list of 4-element lists into a Context.

    Args:
        lst: A list of token representations.

    Returns:
        An immutable Context tuple.
    """
    return tuple(_decode_token(item) for item in lst)


def _context_key(ctx: Context) -> str:
    """Encode a context as a string dict key.

    Args:
        ctx: The context tuple to encode.

    Returns:
        A stable string key; empty string for the empty context.
    """
    if not ctx:
        return ""
    return "|".join(";".join(t) for t in ctx)


def _decode_context_key(key: str) -> Context:
    """Decode a string dict key into a Context.

    Args:
        key: A string produced by _context_key().

    Returns:
        An immutable Context tuple.
    """
    if key == "":
        return ()
    parts = key.split("|")
    tokens: list[Token] = []
    for part in parts:
        fields = part.split(";")
        if len(fields) != 4:
            raise ValueError(f"Malformed context key part: {part!r}")
        tokens.append((fields[0], fields[1], fields[2], fields[3]))
    return tuple(tokens)


def _token_key(t: Token) -> str:
    """Encode a token as a string dict key.

    Args:
        t: A 4-tuple Token.

    Returns:
        A stable string key.
    """
    return ";".join(t)


def _decode_token_key(key: str) -> Token:
    """Decode a string token key into a Token.

    Args:
        key: A string produced by _token_key().

    Returns:
        A Token 4-tuple.

    Raises:
        ValueError: If the key does not split into exactly 4 parts.
    """
    parts = key.split(";")
    if len(parts) != 4:
        raise ValueError(f"Malformed token key: {key!r}")
    return (parts[0], parts[1], parts[2], parts[3])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def serialize(model: MarkovModel) -> str:
    """Serialize a MarkovModel to a JSON string.

    Args:
        model: The trained MarkovModel to serialize.

    Returns:
        A JSON string representing the model.
    """
    doc: dict[str, Any] = {
        "schema_version": "v1",
        "k_star": model.k_star,
        "m": model.m,
        "N": model.N,
        "bic_score": model.bic_score,
        "training_sequences_count": model.training_sequences_count,
        "sigma": [_encode_token(t) for t in sorted(model.sigma)],
        "retained_contexts": [
            _encode_context(ctx)
            for ctx in sorted(model.retained_contexts, key=len)
        ],
        "transition": {
            _context_key(ctx): {
                _token_key(tok): prob
                for tok, prob in tok_probs.items()
            }
            for ctx, tok_probs in model.transition.items()
        },
        "epsilon": {
            _context_key(ctx): eps
            for ctx, eps in model.epsilon.items()
        },
    }
    return json.dumps(doc, sort_keys=True, allow_nan=False)


def deserialize(raw_json: str) -> MarkovModel:
    """Deserialize a JSON string into a MarkovModel.

    Args:
        raw_json: JSON string produced by serialize().

    Returns:
        A reconstructed MarkovModel.

    Raises:
        ValueError: If the schema_version is not "v1" or the JSON is malformed.
        json.JSONDecodeError: If raw_json is not valid JSON.
    """
    doc = json.loads(raw_json)
    schema_version = doc.get("schema_version")
    if schema_version != "v1":
        raise ValueError(
            f"Unsupported MarkovModel schema_version: {schema_version!r}"
        )

    sigma: frozenset[Token] = frozenset(
        _decode_token(t) for t in doc["sigma"]
    )

    retained_contexts: frozenset[Context] = frozenset(
        _decode_context(ctx_list) for ctx_list in doc["retained_contexts"]
    )

    transition: dict[Context, dict[Token, float]] = {
        _decode_context_key(ctx_key): {
            _decode_token_key(tok_key): float(prob)
            for tok_key, prob in tok_probs.items()
        }
        for ctx_key, tok_probs in doc["transition"].items()
    }

    epsilon: dict[Context, float] = {
        _decode_context_key(ctx_key): float(eps)
        for ctx_key, eps in doc["epsilon"].items()
    }

    return MarkovModel(
        sigma=sigma,
        k_star=int(doc["k_star"]),
        retained_contexts=retained_contexts,
        transition=transition,
        epsilon=epsilon,
        bic_score=float(doc["bic_score"]),
        N=int(doc["N"]),
        m=int(doc["m"]),
        training_sequences_count=int(doc["training_sequences_count"]),
    )
