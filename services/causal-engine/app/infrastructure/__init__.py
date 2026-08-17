"""
causal-engine infrastructure layer.

Concrete adapters for:
- asyncpg PostgreSQL BDG/attribution repository
- Redis Streams consumer for drift event messages
- NetworkX graph store for BDG construction
- DoWhy causal estimator adapter
- XGBoost PCEPS scoring adapter
"""
