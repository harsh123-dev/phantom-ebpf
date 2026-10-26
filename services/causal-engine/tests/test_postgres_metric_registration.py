"""Runtime metrics must not collide with metrics registered by phantom-core."""


def test_causal_postgres_metric_registers_with_a_unique_name() -> None:
    from prometheus_client import REGISTRY

    import phantom_core.metrics  # noqa: F401 - register core metrics first
    from app.infrastructure import postgres_repository  # noqa: F401

    names = REGISTRY._names_to_collectors
    assert "phantom_postgres_operation_duration_seconds" in names
    assert "phantom_causal_engine_postgres_operation_duration_seconds" in names
