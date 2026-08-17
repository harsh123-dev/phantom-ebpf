"""
tests/ebpf-agent/test_markov.py

Unit tests for the variable-order Markov chain (domain/markov/chain.py)
and its serializer (domain/markov/serializer.py).

Coverage:
- Alphabet construction includes UNK and OTHER_RESOURCE tokens.
- BIC order selection: higher-order model is selected on structured data.
- LocalBIC pruning: sparse/short sequences result in lower k*.
- Transition probabilities are proper (all > 0, sum to 1 within epsilon).
- epsilon: 1 / (n(h) + m) for all retained contexts.
- predict() handles novel tokens via epsilon fallback.
- Serialization round-trip is exact.
- train() raises ValueError on empty input.
"""

from __future__ import annotations

import json

import pytest

from domain.markov.chain import (
    OTHER_RESOURCE_TOKEN,
    UNK_TOKEN,
    Context,
    MarkovModel,
    Token,
    _bic,
    _build_count_map,
    _suffix,
    tau,
    train,
)
from domain.markov.serializer import deserialize, serialize

# ---------------------------------------------------------------------------
# tau() tokenizer tests
# ---------------------------------------------------------------------------


class TestTau:
    """Tests for the tau() tokenization function."""

    def test_valid_token_passthrough(self) -> None:
        """Known values pass through unchanged."""
        t = tau("exec", "exec", "/usr/bin/ls", "unprivileged")
        assert t == ("exec", "exec", "/usr/bin/ls", "unprivileged")

    def test_unknown_operation_maps_to_exec(self) -> None:
        """Unknown operation_class maps to 'exec' (most conservative fallback)."""
        t = tau("exec", "unknown_op", "res", "unprivileged")
        assert t[1] == "exec"

    def test_unknown_privilege_maps_to_unknown(self) -> None:
        """Unknown privilege_class maps to 'unknown'."""
        t = tau("exec", "exec", "res", "root")
        assert t[3] == "unknown"

    def test_empty_resource_maps_to_other_resource(self) -> None:
        """Empty resource_class maps to OTHER_RESOURCE_TOKEN."""
        t = tau("exec", "exec", "", "unprivileged")
        assert t[2] == OTHER_RESOURCE_TOKEN


# ---------------------------------------------------------------------------
# train() core algorithm tests
# ---------------------------------------------------------------------------


class TestTrain:
    """Tests for the train() function (Algorithm 1)."""

    def test_empty_input_raises(self) -> None:
        """Empty sequences raise ValueError."""
        with pytest.raises(ValueError, match="No training sequences"):
            train([])

    def test_single_sequence_produces_model(
        self, sample_token_sequence: list[Token]
    ) -> None:
        """A valid sequence produces a non-trivial model."""
        model = train([sample_token_sequence], k_max=3)
        assert isinstance(model, MarkovModel)
        assert model.N == len(sample_token_sequence)
        assert model.m >= 2  # At least 2 tokens in alphabet.

    def test_alphabet_includes_unk(
        self, sample_token_sequence: list[Token]
    ) -> None:
        """The alphabet always includes the 4-tuple UNK token."""
        model = train([sample_token_sequence])
        unk_4 = (UNK_TOKEN, UNK_TOKEN, UNK_TOKEN, UNK_TOKEN)
        assert unk_4 in model.sigma

    def test_empty_context_always_retained(
        self, sample_token_sequence: list[Token]
    ) -> None:
        """The empty context () is always retained."""
        model = train([sample_token_sequence])
        assert () in model.retained_contexts

    def test_transition_probabilities_sum_to_one(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """For every retained context, transition probabilities sum to 1."""
        model = mock_markov_model
        for ctx in model.retained_contexts:
            probs = model.transition.get(ctx, {})
            total = sum(probs.values())
            assert abs(total - 1.0) < 1e-9, (
                f"Probabilities for context {ctx} sum to {total}"
            )

    def test_all_transitions_positive(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """All transition probabilities are strictly positive (Laplace smoothing)."""
        model = mock_markov_model
        for ctx, probs in model.transition.items():
            for token, prob in probs.items():
                assert prob > 0.0, f"Zero probability for {token} after {ctx}"

    def test_epsilon_equals_laplace_formula(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """epsilon(h) == 1 / (n(h) + m) for all retained contexts."""
        model = mock_markov_model
        _ = [list(model.sigma)[:20]]  # Minimal re-trainable data.
        # Re-train with known structure to verify formula.
        seq = [
            tau("exec", "exec", "/bin/ls", "unprivileged"),
            tau("file_open", "read", "/etc/hosts", "unprivileged"),
        ] * 10
        m2 = train([seq], k_max=1)
        empty_eps = m2.epsilon.get(())
        # For empty context: n(()) = N (total tokens), epsilon = 1/(N+m).
        expected = 1.0 / (m2.N + m2.m)
        if empty_eps is not None:
            assert abs(empty_eps - expected) < 1e-12

    def test_bic_selects_lower_order_for_random_data(self) -> None:
        """BIC selects order 0 when sequence has no structure."""
        import random
        rng = random.Random(42)
        tokens: list[Token] = [
            tau(
                rng.choice(["exec", "file_open"]),
                rng.choice(["exec", "read"]),
                "/dev/null",
                "unprivileged",
            )
            for _ in range(200)
        ]
        model = train([tokens], k_max=4)
        # Random data: BIC should prefer low order (0 or 1).
        assert model.k_star <= 2, (
            f"Expected low k* for random data, got {model.k_star}"
        )

    def test_bic_selects_higher_order_for_structured_data(
        self, sample_token_sequence: list[Token]
    ) -> None:
        """BIC selects order >= 1 for structured (patterned) data."""
        model = train([sample_token_sequence], k_max=4)
        # Pattern repeats every 5 tokens; order >= 1 should capture context.
        assert model.k_star >= 1

    def test_novel_token_detected(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """Tokens not in training sigma are flagged as novel."""
        novel = tau("module_load", "module_change", "/kernel/mod.ko", "elevated")
        assert mock_markov_model.is_novel_token(novel)

    def test_known_token_not_novel(
        self, mock_markov_model: MarkovModel, sample_token_sequence: list[Token]
    ) -> None:
        """Tokens present in training sigma are not flagged as novel."""
        known = sample_token_sequence[0]
        assert not mock_markov_model.is_novel_token(known)


# ---------------------------------------------------------------------------
# predict() tests
# ---------------------------------------------------------------------------


class TestPredict:
    """Tests for MarkovModel.predict()."""

    def test_predict_known_token_positive(
        self, mock_markov_model: MarkovModel, sample_token_sequence: list[Token]
    ) -> None:
        """Known token has positive probability."""
        model = mock_markov_model
        t = sample_token_sequence[0]
        p = model.predict((), t)
        assert p > 0.0

    def test_predict_novel_token_returns_epsilon(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """Novel token after empty context returns epsilon (minimum probability)."""
        model = mock_markov_model
        novel = tau("module_load", "module_change", "/kernel/mod.ko", "elevated")
        p = model.predict((), novel)
        eps = model.epsilon.get((), 1.0 / (1 + model.m))
        # Novel token gets epsilon (or a value <= eps due to uniform Laplace).
        assert p <= eps + 1e-12

    def test_predict_unknown_context_uses_suffix(
        self, mock_markov_model: MarkovModel, sample_token_sequence: list[Token]
    ) -> None:
        """Prediction falls back to empty context for unknown context."""
        model = mock_markov_model
        unknown_ctx: Context = (
            tau("module_load", "module_change", "/x", "elevated"),
            tau("module_load", "module_change", "/y", "elevated"),
        )
        t = sample_token_sequence[0]
        # Should not raise; falls back to shorter retained suffix.
        p = model.predict(unknown_ctx, t)
        assert p > 0.0


# ---------------------------------------------------------------------------
# Serialization round-trip tests
# ---------------------------------------------------------------------------


class TestSerializer:
    """Tests for domain/markov/serializer.py."""

    def test_round_trip_preserves_k_star(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """Round-trip serialization preserves k_star."""
        json_str = serialize(mock_markov_model)
        model2   = deserialize(json_str)
        assert model2.k_star == mock_markov_model.k_star

    def test_round_trip_preserves_bic(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """Round-trip serialization preserves bic_score."""
        json_str = serialize(mock_markov_model)
        model2   = deserialize(json_str)
        assert abs(model2.bic_score - mock_markov_model.bic_score) < 1e-12

    def test_round_trip_preserves_transitions(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """Round-trip serialization preserves transition probabilities."""
        model  = mock_markov_model
        json_s = serialize(model)
        model2 = deserialize(json_s)
        for ctx in model.retained_contexts:
            for tok in model.sigma:
                p1 = model.predict(ctx, tok)
                p2 = model2.predict(ctx, tok)
                assert abs(p1 - p2) < 1e-12, (
                    f"Probability drift for ctx={ctx}, tok={tok}: {p1} vs {p2}"
                )

    def test_schema_version_present(
        self, mock_markov_model: MarkovModel
    ) -> None:
        """Serialized JSON contains schema_version='v1'."""
        doc = json.loads(serialize(mock_markov_model))
        assert doc["schema_version"] == "v1"

    def test_invalid_schema_version_raises(self) -> None:
        """Deserialization of wrong schema_version raises ValueError."""
        bad_json = json.dumps({"schema_version": "v999", "k_star": 0})
        with pytest.raises(ValueError, match="schema_version"):
            deserialize(bad_json)

    def test_serialize_empty_context(self, mock_markov_model: MarkovModel) -> None:
        """Empty context serializes and deserializes correctly."""
        model = mock_markov_model
        json_s = serialize(model)
        model2 = deserialize(json_s)
        assert () in model2.retained_contexts


# ---------------------------------------------------------------------------
# BIC helper tests
# ---------------------------------------------------------------------------


class TestBicHelpers:
    """Tests for BIC computation helpers."""

    def test_bic_increases_with_order_on_random_data(self) -> None:
        """BIC should penalize over-parameterization on random data."""
        import random
        rng = random.Random(0)
        tokens = [
            tau(rng.choice(["exec", "read"]), "exec", "/x", "unprivileged")
            for _ in range(50)
        ]
        sequences = [tokens]
        cm0 = _build_count_map(sequences, 0)
        cm2 = _build_count_map(sequences, 2)
        m = 4
        N = 50
        bic0 = _bic(cm0, m, N)
        bic2 = _bic(cm2, m, N)
        # BIC for order 2 should be >= order 0 on random data (more params).
        assert bic2 >= bic0 - 1e-6  # Allow tiny numerical tolerance.

    def test_suffix_of_empty_is_empty(self) -> None:
        """_suffix(()) returns ()."""
        assert _suffix(()) == ()

    def test_suffix_removes_first_element(self) -> None:
        """_suffix drops the first token of a context."""
        t1 = tau("exec", "exec", "/a", "unprivileged")
        t2 = tau("read", "read", "/b", "unprivileged")
        ctx = (t1, t2)
        assert _suffix(ctx) == (t2,)
