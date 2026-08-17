"""
causal-engine domain causal SCM builder.

Implements the NetworkX → DoWhy CausalModel construction from
handoff §6.3 and Algorithm 4 §6.4.

Construction steps:
1. Accept a TemporalDAGProjection and a list of CausalObservations.
2. Build a pandas DataFrame from the observations.
3. Build a NetworkX DiGraph from the projected variable nodes/edges.
4. Convert the graph to GML for the pinned DoWhy release.
5. Construct a DoWhy CausalModel with treatment, outcome, and graph.
6. Check for non-identifiability conditions:
   - Treatment/outcome in unresolved cycle → not_identifiable
   - No variation in treatment or outcome → not_identifiable
   - Positivity failure → not_identifiable
7. Return a CausalModelHandle or raise the appropriate exception.

No framework imports except DoWhy (unavoidable for SCM construction).
"""

from __future__ import annotations

import io
from typing import Any

import networkx as nx
import pandas as pd
import structlog

from app.domain.entities import (
    CausalModelHandle,
    CausalObservation,
    TemporalDAGProjection,
)
from app.domain.exceptions import (
    CausalModelConstructionError,
    GraphCycleError,
    InsufficientVariationError,
    PositivityFailureError,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Positivity diagnostic (§6.4 line 09–10)
# ---------------------------------------------------------------------------


def check_positivity(
    df: pd.DataFrame,
    treatment_col: str,
    covariate_cols: list[str],
    min_overlap_fraction: float = 0.05,
) -> bool:
    """Check the positivity assumption for causal identification.

    For each unique covariate stratum, both treatment=0 and treatment=1
    must appear with at least ``min_overlap_fraction`` of the stratum size.

    Args:
        df: Causal data table.
        treatment_col: Treatment column name.
        covariate_cols: List of covariate column names.
        min_overlap_fraction: Minimum fraction for overlap.

    Returns:
        True if positivity holds, False otherwise.
    """
    if not covariate_cols:
        # No covariates: check that both treatment values exist.
        return bool(df[treatment_col].nunique() >= 2)

    # Discretize continuous covariates into quartiles for checking.
    df_check = df.copy()
    for col in covariate_cols:
        if df_check[col].nunique() > 4:
            df_check[col] = pd.qcut(df_check[col], q=4, labels=False, duplicates="drop")

    # Group by covariate strata.
    try:
        grouped = df_check.groupby(covariate_cols, observed=True)
        for _name, group in grouped:
            if len(group) < 2:
                continue
            treated = (group[treatment_col] == 1).sum()
            control = (group[treatment_col] == 0).sum()
            n = len(group)
            if treated / n < min_overlap_fraction or control / n < min_overlap_fraction:
                return False
    except Exception:  # noqa: BLE001
        # If grouping fails (e.g., all identical), fall back to global check.
        return bool(df[treatment_col].nunique() >= 2)

    return True


# ---------------------------------------------------------------------------
# SCM Builder
# ---------------------------------------------------------------------------


def build_causal_data_table(
    observations: list[CausalObservation],
    treatment_name: str,
    outcome_name: str,
    covariate_names: list[str],
) -> pd.DataFrame:
    """Build a pandas DataFrame from causal observations.

    Each CausalObservation becomes one row. The treatment and outcome columns
    are binary integers. Covariate columns are filled from the observation's
    covariates dict; missing values are filled with 0.

    Args:
        observations: List of CausalObservation dataclass instances.
        treatment_name: Column name for the treatment variable.
        outcome_name: Column name for the outcome variable.
        covariate_names: Ordered list of covariate column names.

    Returns:
        A pandas DataFrame with columns [treatment, outcome, covariates...].

    Raises:
        InsufficientVariationError: If treatment or outcome has no variation.
    """
    rows: list[dict[str, Any]] = []
    for obs in observations:
        row: dict[str, Any] = {
            treatment_name: obs.treatment_value,
            outcome_name: obs.outcome_value,
        }
        for cov_name in covariate_names:
            row[cov_name] = obs.covariates.get(cov_name, 0.0)
        rows.append(row)

    df = pd.DataFrame(rows)

    # §6.4 lines 07–08: check for variation.
    if df[treatment_name].nunique() < 2:
        raise InsufficientVariationError(treatment_name)
    if df[outcome_name].nunique() < 2:
        raise InsufficientVariationError(outcome_name)

    return df


def build_scm_graph(
    projection: TemporalDAGProjection,
    treatment_name: str,
    outcome_name: str,
    covariate_names: list[str],
) -> nx.DiGraph:
    """Build a NetworkX DiGraph representing the SCM from a projection.

    Nodes are variable names (treatment, outcome, covariates). Edges are
    directed causal relationships from the temporal DAG projection.

    The graph uses only the semantic variable names (not windowed tuples)
    for DoWhy compatibility.

    Args:
        projection: The TemporalDAGProjection from BDG.
        treatment_name: Treatment variable name.
        outcome_name: Outcome variable name.
        covariate_names: List of covariate variable names.

    Returns:
        A NetworkX DiGraph suitable for DoWhy CausalModel construction.
    """
    dag = nx.DiGraph()

    # Add all variable nodes.
    all_vars = {treatment_name, outcome_name} | set(covariate_names)
    for var in all_vars:
        dag.add_node(var)

    # Collect unique semantic variable pairs from the projection.
    # The projection has (var, window) tuples; we collapse windows.
    projected_var_pairs: set[tuple[str, str]] = set()
    for (src_var, _src_w), (tgt_var, _tgt_w) in projection.projected_edges:
        if src_var != tgt_var:
            projected_var_pairs.add((src_var, tgt_var))

    # Add edges for projected pairs that involve known SCM variables.
    for src, tgt in projected_var_pairs:
        if src in all_vars and tgt in all_vars:
            dag.add_edge(src, tgt)

    # Ensure treatment → outcome edge exists (the core causal question).
    if not dag.has_edge(treatment_name, outcome_name):
        dag.add_edge(treatment_name, outcome_name)

    # Ensure covariates → treatment and covariates → outcome edges.
    # Per handoff §6.1: pre-treatment covariates cause both treatment
    # assignment and outcome through confounding paths.
    for cov in covariate_names:
        if not dag.has_edge(cov, treatment_name):
            dag.add_edge(cov, treatment_name)
        if not dag.has_edge(cov, outcome_name):
            dag.add_edge(cov, outcome_name)

    return dag


def graph_to_gml(dag: nx.DiGraph) -> str:
    """Serialize a NetworkX DiGraph to GML string.

    DoWhy accepts GML graph serialization. This uses NetworkX's built-in
    GML writer to produce a string representation.

    Args:
        dag: A NetworkX DiGraph.

    Returns:
        GML string representation of the graph.
    """
    buf = io.BytesIO()
    nx.write_gml(dag, buf)
    return buf.getvalue().decode("utf-8")


def construct_causal_model(
    projection: TemporalDAGProjection,
    observations: list[CausalObservation],
    treatment_name: str,
    outcome_name: str,
    covariate_names: list[str],
) -> CausalModelHandle:
    """Construct a DoWhy CausalModel from a projection and observations.

    Implements the construction sequence from handoff §6.3:
    1. Check non-identifiability pre-conditions.
    2. Build the causal data table.
    3. Build the SCM graph.
    4. Construct the DoWhy CausalModel.

    Args:
        projection: The TemporalDAGProjection from BDG.
        observations: List of CausalObservation rows.
        treatment_name: Treatment variable name.
        outcome_name: Outcome variable name.
        covariate_names: List of covariate variable names.

    Returns:
        A CausalModelHandle wrapping the DoWhy model.

    Raises:
        GraphCycleError: If treatment or outcome is in an unresolved cycle.
        InsufficientVariationError: If treatment or outcome has no variation.
        PositivityFailureError: If the positivity check fails.
        CausalModelConstructionError: If DoWhy construction fails.
    """
    bound_log = log.bind(
        treatment=treatment_name,
        outcome=outcome_name,
        covariate_count=len(covariate_names),
        observation_count=len(observations),
    )

    # §6.4 lines 03–04: check for cycles in treatment/outcome.
    if projection.treatment_or_outcome_in_cycle:
        raise GraphCycleError(
            scc_nodes=[treatment_name, outcome_name],
            message="Treatment or outcome in unresolved BDG cycle",
        )

    # Build data table (checks variation internally).
    bound_log.info("scm_builder.building_data_table")
    df = build_causal_data_table(
        observations=observations,
        treatment_name=treatment_name,
        outcome_name=outcome_name,
        covariate_names=covariate_names,
    )

    # §6.4 lines 09–10: positivity check.
    if not check_positivity(df, treatment_name, covariate_names):
        raise PositivityFailureError(
            f"Insufficient treatment/control overlap across covariates "
            f"for {treatment_name}"
        )

    # Build the SCM graph.
    bound_log.info("scm_builder.building_graph")
    scm_dag = build_scm_graph(
        projection=projection,
        treatment_name=treatment_name,
        outcome_name=outcome_name,
        covariate_names=covariate_names,
    )

    # Verify the SCM graph is a DAG.
    if not nx.is_directed_acyclic_graph(scm_dag):
        cycles = list(nx.simple_cycles(scm_dag))
        raise GraphCycleError(
            scc_nodes=[str(n) for cycle in cycles for n in cycle],
            message=f"SCM graph contains {len(cycles)} cycle(s)",
        )

    # Serialize graph to GML.
    gml_str = graph_to_gml(scm_dag)
    bound_log.info("scm_builder.graph_serialized", gml_length=len(gml_str))

    # Construct DoWhy CausalModel.
    try:
        import dowhy

        model = dowhy.CausalModel(
            data=df,
            treatment=treatment_name,
            outcome=outcome_name,
            graph=gml_str,
        )
    except Exception as exc:
        raise CausalModelConstructionError(
            f"DoWhy CausalModel construction failed: {exc}"
        ) from exc

    bound_log.info("scm_builder.model_constructed")

    return CausalModelHandle(
        model=model,
        graph_gml=gml_str,
        treatment_name=treatment_name,
        outcome_name=outcome_name,
        covariate_names=covariate_names,
    )
