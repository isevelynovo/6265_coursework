"""
Policy Analyzer Module
======================
Static analyzer for the Policy-Driven Zero-Trust Data Access Gateway.

Detects the following classes of policy / governance issues:

  1. DeadRuleDetector             - rules referencing tags not in the catalog
  2. CoverageGapDetector          - (role, tag) pairs without explicit rules
  3. AlgorithmCompatibilityChecker- mask algorithm incompatible with column dtype
  4. PolicyCatalogDriftDetector   - column tags changed historically (audit log)
  5. AuditChainVerifier           - hash chain integrity, resets, tampering

Also provides:
  - Role Access Matrix (what each role sees on each column right now)
  - Policy Dry-Run / Diff (compare a candidate policy against the current policy)
  - Streamlit UI renderer: render_policy_analyzer_tab()

This module is intentionally self-contained: import the public functions from
``app.py`` and call ``render_policy_analyzer_tab(...)`` inside the new tab.
"""

from __future__ import annotations

import os
import json
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple

import pandas as pd
import streamlit as st


# =============================================================
# Issue model
# =============================================================

@dataclass
class PolicyIssue:
    severity: str             # "CRITICAL" | "WARNING" | "INFO"
    detector: str             # which detector produced it
    category: str             # short category label
    message: str              # human-readable description
    suggestion: str = ""      # recommended fix
    role: Optional[str] = None
    tag: Optional[str] = None
    column: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# =============================================================
# Detector 1: Dead Rules
#   A "dead rule" is a rule that references a tag which no
#   current column carries. The rule can never fire.
# =============================================================

def detect_dead_rules(policy: dict, catalog: dict) -> List[PolicyIssue]:
    issues: List[PolicyIssue] = []
    tags_in_use = {
        meta.get("tag")
        for meta in catalog.get("columns", {}).values()
        if meta.get("tag")
    }

    for role, role_policy in policy.get("roles", {}).items():
        for tag, rule in role_policy.get("rules", {}).items():
            if tag not in tags_in_use:
                issues.append(PolicyIssue(
                    severity="WARNING",
                    detector="DeadRuleDetector",
                    category="Dead Rule",
                    role=role,
                    tag=tag,
                    message=(
                        f"Role '{role}' has a rule for tag '{tag}', "
                        f"but no column in the current catalog uses this tag. "
                        f"The rule will never be triggered."
                    ),
                    suggestion=(
                        f"Remove the '{tag}' rule from role '{role}', "
                        f"or tag a column as '{tag}' if this rule is intended for future use."
                    ),
                ))
    return issues


# =============================================================
# Detector 2: Coverage Gaps
#   For every (role, tag-in-use) pair, if the role has no
#   explicit rule, the role falls back to default_action.
#   Silent drops are dangerous and worth a warning.
# =============================================================

def detect_coverage_gaps(policy: dict, catalog: dict) -> List[PolicyIssue]:
    issues: List[PolicyIssue] = []
    tags_in_use = {
        meta.get("tag")
        for meta in catalog.get("columns", {}).values()
        if meta.get("tag")
    }

    for role, role_policy in policy.get("roles", {}).items():
        default = role_policy.get("default_action", "drop")
        rules = role_policy.get("rules", {})

        for tag in tags_in_use:
            if tag in rules:
                continue

            if default == "allow":
                # Default allow means tag will be exposed in plaintext.
                issues.append(PolicyIssue(
                    severity="INFO",
                    detector="CoverageGapDetector",
                    category="Implicit Allow",
                    role=role,
                    tag=tag,
                    message=(
                        f"Role '{role}' has no explicit rule for tag '{tag}'. "
                        f"default_action='allow' means columns of this tag will be returned as plaintext."
                    ),
                    suggestion=(
                        "Confirm that plaintext access is intentional for this role. "
                        "If not, add an explicit rule."
                    ),
                ))
            else:
                # Default drop means tag is silently suppressed.
                issues.append(PolicyIssue(
                    severity="WARNING",
                    detector="CoverageGapDetector",
                    category="Silent Drop",
                    role=role,
                    tag=tag,
                    message=(
                        f"Role '{role}' has no explicit rule for tag '{tag}'. "
                        f"default_action='{default}' means columns of this tag will be silently dropped."
                    ),
                    suggestion=(
                        f"Add an explicit rule for tag '{tag}' under role '{role}' to make the "
                        "behaviour intentional and auditable."
                    ),
                ))
    return issues


# =============================================================
# Detector 3: Algorithm <-> Column Type Compatibility
#   Some masking algorithms (e.g. generalize_numeric, laplace_noise)
#   require numeric dtypes. If the catalog says a Quasi_PII_Age
#   column is 'object' (string), the algorithm will silently fail
#   and the column will fall back to drop.
# =============================================================

NUMERIC_HINTS = ("int", "float", "number")
STRING_HINTS  = ("object", "str", "string", "category")

ALGORITHM_REQUIREMENT = {
    "generalize_numeric": "numeric",
    "laplace_noise":      "numeric",
    "mask_string_tail":   "string",
    "hash_string":        "any",
    "redact":             "any",
}


def _is_numeric(dtype: str) -> bool:
    return any(t in dtype.lower() for t in NUMERIC_HINTS)


def _is_string(dtype: str) -> bool:
    return any(t in dtype.lower() for t in STRING_HINTS)


def detect_algorithm_incompatibility(policy: dict, catalog: dict) -> List[PolicyIssue]:
    issues: List[PolicyIssue] = []

    for role, role_policy in policy.get("roles", {}).items():
        for tag, rule in role_policy.get("rules", {}).items():
            if rule.get("action") != "mask":
                continue

            algo = rule.get("algorithm")
            req  = ALGORITHM_REQUIREMENT.get(algo)
            if req is None or req == "any":
                continue

            # Find columns that carry this tag.
            affected = [
                (col, meta.get("type", ""))
                for col, meta in catalog.get("columns", {}).items()
                if meta.get("tag") == tag
            ]

            for col, dtype in affected:
                ok = (
                    (req == "numeric" and _is_numeric(dtype)) or
                    (req == "string"  and _is_string(dtype))
                )
                if ok:
                    continue

                issues.append(PolicyIssue(
                    severity="CRITICAL",
                    detector="AlgorithmCompatibilityChecker",
                    category="Algo-Type Mismatch",
                    role=role,
                    tag=tag,
                    column=col,
                    message=(
                        f"Role '{role}' applies algorithm '{algo}' to column '{col}' "
                        f"(tag={tag}, dtype={dtype}), but '{algo}' requires {req} data. "
                        f"Queries by this role will silently fail and the column will be dropped."
                    ),
                    suggestion=(
                        f"Use a {req}-compatible algorithm, change the column dtype, "
                        f"or re-tag the column to a more appropriate ontology tag."
                    ),
                ))
    return issues


# =============================================================
# Detector 4: Policy-Catalog Drift
#   Parse the audit log execution traces to learn how each
#   column has been tagged historically. If a column's tag in
#   the current catalog is different from what was used in past
#   queries, that's drift: past audit decisions no longer
#   reflect current policy semantics.
# =============================================================

def detect_policy_catalog_drift(audit_path: str, catalog: dict) -> List[PolicyIssue]:
    issues: List[PolicyIssue] = []
    if not os.path.exists(audit_path) or os.path.getsize(audit_path) == 0:
        return issues

    history: Dict[str, set] = {}

    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            for trace in entry.get("execution_trace", []):
                if "Column '" not in trace or "(Tag:" not in trace:
                    continue
                try:
                    c_start = trace.index("Column '") + len("Column '")
                    c_end   = trace.index("'", c_start)
                    col_name = trace[c_start:c_end]

                    t_start = trace.index("(Tag:") + len("(Tag:")
                    t_end   = trace.index(")", t_start)
                    tag_name = trace[t_start:t_end].strip()

                    history.setdefault(col_name, set()).add(tag_name)
                except ValueError:
                    continue

    current = {
        col: meta.get("tag")
        for col, meta in catalog.get("columns", {}).items()
    }

    for col, tags_seen in history.items():
        cur_tag = current.get(col)
        if cur_tag is None:
            # Column was historically queried but is no longer in catalog.
            issues.append(PolicyIssue(
                severity="INFO",
                detector="PolicyCatalogDriftDetector",
                category="Dropped Column",
                column=col,
                message=(
                    f"Column '{col}' appears in the audit log but is no longer in the catalog "
                    f"(historical tags: {sorted(tags_seen)})."
                ),
                suggestion=(
                    "If the column was renamed or removed, document the change. "
                    "Past audit entries cannot be re-evaluated against the current policy."
                ),
            ))
            continue

        drift = tags_seen - {cur_tag}
        if drift:
            issues.append(PolicyIssue(
                severity="WARNING",
                detector="PolicyCatalogDriftDetector",
                category="Tag Drift",
                column=col,
                tag=cur_tag,
                message=(
                    f"Column '{col}' has been tagged differently in the past. "
                    f"Historical tags: {sorted(tags_seen)} | Current tag: '{cur_tag}'. "
                    f"Past audit decisions may not reflect current policy."
                ),
                suggestion=(
                    "Verify the tag change was intentional. Check whether existing role policies "
                    "for the new tag still give the correct protection level. Consider versioning "
                    "the catalog and binding each audit entry to a catalog version."
                ),
            ))
    return issues


# =============================================================
# Detector 5: Audit Chain Verifier
#   Each audit entry stores a SHA-256 hash of (prev_hash + canonical_entry).
#   Verify:
#     - the recomputed hash matches the stored hash (no tampering)
#     - prev_hash chains correctly to the previous entry
#     - chain resets (prev_hash = GENESIS mid-log) are flagged
#     - legacy entries without a hash field are counted
# =============================================================

def verify_audit_chain(audit_path: str) -> Tuple[List[PolicyIssue], dict]:
    issues: List[PolicyIssue] = []
    stats = {
        "total_entries":     0,
        "legacy_no_hash":    0,
        "valid_hash":        0,
        "tampered_hash":     0,
        "chain_resets":      0,
        "broken_links":      0,
        "first_hashed_line": None,
    }
    if not os.path.exists(audit_path) or os.path.getsize(audit_path) == 0:
        return issues, stats

    last_valid_hash = "GENESIS"
    line_no = 0

    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            line_no += 1
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            stats["total_entries"] += 1

            if "hash" not in entry:
                stats["legacy_no_hash"] += 1
                continue

            if stats["first_hashed_line"] is None:
                stats["first_hashed_line"] = line_no

            stored_hash = entry["hash"]
            stored_prev = entry.get("prev_hash", "GENESIS")

            # Recompute hash exactly as gateway_engine._compute_entry_hash does.
            entry_no_hash = {k: v for k, v in entry.items() if k != "hash"}
            canonical    = json.dumps(entry_no_hash, sort_keys=True, separators=(",", ":"))
            recomputed   = hashlib.sha256((stored_prev + canonical).encode("utf-8")).hexdigest()

            if recomputed != stored_hash:
                stats["tampered_hash"] += 1
                issues.append(PolicyIssue(
                    severity="CRITICAL",
                    detector="AuditChainVerifier",
                    category="Tampered Hash",
                    message=(
                        f"Line {line_no}: stored hash does not match recomputed hash. "
                        "Either the entry was tampered with after writing, or the hash "
                        "function in the writer drifted from the verifier."
                    ),
                    suggestion="Investigate audit log integrity immediately.",
                ))
            else:
                stats["valid_hash"] += 1

            # Chain continuity checks (only after the first hashed line).
            if last_valid_hash != "GENESIS":
                if stored_prev == "GENESIS":
                    stats["chain_resets"] += 1
                    issues.append(PolicyIssue(
                        severity="WARNING",
                        detector="AuditChainVerifier",
                        category="Chain Reset",
                        message=(
                            f"Line {line_no}: prev_hash is 'GENESIS' but the chain was already "
                            "active. This usually means the container was restarted and "
                            "`_read_last_hash` in gateway_engine.py could not locate the last hash."
                        ),
                        suggestion=(
                            "Make `_read_last_hash` walk back across legacy entries (entries with "
                            "no `hash` field) so the chain survives container restarts."
                        ),
                    ))
                elif stored_prev != last_valid_hash:
                    stats["broken_links"] += 1
                    issues.append(PolicyIssue(
                        severity="CRITICAL",
                        detector="AuditChainVerifier",
                        category="Broken Link",
                        message=(
                            f"Line {line_no}: prev_hash does not match the previous entry's hash. "
                            "The chain is broken; entries may have been inserted, deleted, or reordered."
                        ),
                        suggestion="Manual audit required.",
                    ))

            last_valid_hash = stored_hash

    if stats["legacy_no_hash"] > 0:
        issues.append(PolicyIssue(
            severity="INFO",
            detector="AuditChainVerifier",
            category="Legacy Entries",
            message=(
                f"{stats['legacy_no_hash']} early audit entries were written without a hash chain "
                "and cannot be cryptographically verified."
            ),
            suggestion=(
                "These records pre-date the hash-chain feature. Consider marking them as 'legacy' "
                "in any compliance export."
            ),
        ))

    return issues, stats


# =============================================================
# Role Access Matrix
# =============================================================

def build_role_access_matrix(policy: dict, catalog: dict) -> pd.DataFrame:
    """For each (role, column) cell, return the effective action label."""
    rows = []
    cols = list(catalog.get("columns", {}).keys())

    for role, role_policy in policy.get("roles", {}).items():
        default = role_policy.get("default_action", "drop")
        rules   = role_policy.get("rules", {})
        row = {"Role": role, "Default": default}
        for col in cols:
            tag  = catalog["columns"][col].get("tag", "UNTAGGED")
            rule = rules.get(tag, {"action": default})
            action = rule.get("action", default)
            algo   = rule.get("algorithm")
            if action == "mask" and algo:
                cell = f"MASK[{algo}]"
            else:
                cell = action.upper()
            row[f"{col} ({tag})"] = cell
        rows.append(row)
    return pd.DataFrame(rows)


# =============================================================
# Policy Diff / Dry-Run
# =============================================================

ACTION_STRICTNESS = {"allow": 0, "mask": 1, "drop": 2}


def _classify_change(old_action: str, new_action: str,
                     old_algo: str, new_algo: str) -> str:
    o, n = ACTION_STRICTNESS.get(old_action, 0), ACTION_STRICTNESS.get(new_action, 0)
    if n > o:
        return "STRICTER"
    if n < o:
        return "LOOSER"
    if old_algo != new_algo:
        return "ALGO/PARAM"
    return "UNCHANGED"


def diff_policies(old_policy: dict, new_policy: dict, catalog: dict) -> pd.DataFrame:
    """Compute per-(role, column) differences between two policies."""
    rows = []
    all_roles = (
        set(old_policy.get("roles", {}).keys()) |
        set(new_policy.get("roles", {}).keys())
    )
    cols = list(catalog.get("columns", {}).keys())

    for role in sorted(all_roles):
        old_rp = old_policy.get("roles", {}).get(role, {"default_action": "drop", "rules": {}})
        new_rp = new_policy.get("roles", {}).get(role, {"default_action": "drop", "rules": {}})

        for col in cols:
            tag = catalog["columns"][col].get("tag", "UNTAGGED")

            old_rule = old_rp.get("rules", {}).get(
                tag, {"action": old_rp.get("default_action", "drop")}
            )
            new_rule = new_rp.get("rules", {}).get(
                tag, {"action": new_rp.get("default_action", "drop")}
            )

            old_action = old_rule.get("action", "drop")
            new_action = new_rule.get("action", "drop")
            old_algo   = old_rule.get("algorithm", "") or ""
            new_algo   = new_rule.get("algorithm", "") or ""

            change_type = _classify_change(old_action, new_action, old_algo, new_algo)
            if change_type == "UNCHANGED":
                continue

            rows.append({
                "Role":       role,
                "Column":     col,
                "Tag":        tag,
                "Old Action": old_action,
                "Old Algo":   old_algo,
                "New Action": new_action,
                "New Algo":   new_algo,
                "Change":     change_type,
            })

    return pd.DataFrame(rows)


# =============================================================
# Orchestrator
# =============================================================

def run_full_analysis(policy: dict, catalog: dict, audit_path: str) -> dict:
    issues: List[PolicyIssue] = []
    issues.extend(detect_dead_rules(policy, catalog))
    issues.extend(detect_coverage_gaps(policy, catalog))
    issues.extend(detect_algorithm_incompatibility(policy, catalog))
    issues.extend(detect_policy_catalog_drift(audit_path, catalog))

    chain_issues, chain_stats = verify_audit_chain(audit_path)
    issues.extend(chain_issues)

    by_severity = {"CRITICAL": [], "WARNING": [], "INFO": []}
    for iss in issues:
        by_severity.setdefault(iss.severity, []).append(iss)

    by_detector: Dict[str, List[PolicyIssue]] = {}
    for iss in issues:
        by_detector.setdefault(iss.detector, []).append(iss)

    return {
        "issues":            issues,
        "by_severity":       by_severity,
        "by_detector":       by_detector,
        "audit_chain_stats": chain_stats,
        "summary": {
            "total":    len(issues),
            "critical": len(by_severity["CRITICAL"]),
            "warning":  len(by_severity["WARNING"]),
            "info":     len(by_severity["INFO"]),
        },
    }


# =============================================================
# Streamlit Tab Renderer
# =============================================================

SEVERITY_ICON = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}


def _render_issue_card(issue: PolicyIssue) -> None:
    icon = SEVERITY_ICON.get(issue.severity, "•")
    header = f"{icon}  [{issue.severity}]  {issue.detector}  —  {issue.category}"

    with st.expander(header, expanded=(issue.severity == "CRITICAL")):
        st.markdown(f"**What's wrong:** {issue.message}")
        if issue.suggestion:
            st.markdown(f"**How to fix:** {issue.suggestion}")

        affected_parts = []
        if issue.role:
            affected_parts.append(f"Role: `{issue.role}`")
        if issue.tag:
            affected_parts.append(f"Tag: `{issue.tag}`")
        if issue.column:
            affected_parts.append(f"Column: `{issue.column}`")
        if affected_parts:
            st.markdown("**Affected:** " + "  •  ".join(affected_parts))


def render_policy_analyzer_tab(
    current_policy: dict,
    current_catalog: dict,
    audit_log_path: str,
) -> None:
    """Render Tab 5 — Policy Analyzer.

    Caller should already have:
      - `current_policy`   : dict loaded from policy.json
      - `current_catalog`  : dict loaded from data_catalog.json or session_state
      - `audit_log_path`   : str path to audit.log
    """
    st.header("Policy Analyzer & Conflict Detection")
    st.caption(
        "Static analysis over the current policy, catalog, and audit log. "
        "Detects dead rules, coverage gaps, algorithm-type incompatibilities, "
        "policy/catalog drift, and audit-chain integrity issues."
    )

    # -- Run button -------------------------------------------------
    btn_col, _ = st.columns([1, 5])
    with btn_col:
        if st.button("Run Full Analysis", type="primary", key="run_policy_analysis"):
            with st.spinner("Analyzing policy, catalog, and audit log..."):
                st.session_state.policy_analysis_result = run_full_analysis(
                    policy=current_policy,
                    catalog=current_catalog,
                    audit_path=audit_log_path,
                )

    # -- Results ---------------------------------------------------
    if "policy_analysis_result" in st.session_state:
        analysis = st.session_state.policy_analysis_result

        st.markdown("---")
        st.subheader("Summary")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Issues",  analysis["summary"]["total"])
        m2.metric("🔴 Critical",   analysis["summary"]["critical"])
        m3.metric("🟡 Warning",    analysis["summary"]["warning"])
        m4.metric("🔵 Info",       analysis["summary"]["info"])

        chain = analysis["audit_chain_stats"]
        with st.expander("Audit-chain statistics", expanded=False):
            ac1, ac2, ac3, ac4, ac5 = st.columns(5)
            ac1.metric("Total log entries", chain["total_entries"])
            ac2.metric("Valid hash links",  chain["valid_hash"])
            ac3.metric("Legacy (no hash)",  chain["legacy_no_hash"])
            ac4.metric("Chain resets",      chain["chain_resets"])
            ac5.metric("Broken / tampered", chain["broken_links"] + chain["tampered_hash"])

        st.markdown("---")
        st.subheader("Issues Detected")

        if not analysis["issues"]:
            st.success("No issues detected. Your policy is clean. ✅")
        else:
            f_col1, f_col2 = st.columns([2, 3])
            with f_col1:
                severity_filter = st.multiselect(
                    "Filter by severity:",
                    options=["CRITICAL", "WARNING", "INFO"],
                    default=["CRITICAL", "WARNING", "INFO"],
                    key="severity_filter",
                )
            with f_col2:
                detector_filter = st.multiselect(
                    "Filter by detector:",
                    options=sorted(analysis["by_detector"].keys()),
                    default=sorted(analysis["by_detector"].keys()),
                    key="detector_filter",
                )

            filtered = [
                iss for iss in analysis["issues"]
                if iss.severity in severity_filter and iss.detector in detector_filter
            ]

            if not filtered:
                st.info("No issues match the current filter.")
            else:
                st.caption(f"Showing {len(filtered)} of {len(analysis['issues'])} issues.")
                for iss in filtered:
                    _render_issue_card(iss)

    # -- Role Access Matrix ----------------------------------------
    st.markdown("---")
    st.subheader("Role Access Matrix")
    st.caption("What each role currently sees on each column under the live policy.")

    matrix = build_role_access_matrix(current_policy, current_catalog)
    st.dataframe(matrix, use_container_width=True, hide_index=True)

    # -- Policy Dry-Run --------------------------------------------
    st.markdown("---")
    st.subheader("Policy Dry-Run / Diff")
    st.caption(
        "Paste a candidate policy JSON below. The analyzer will compute how access changes "
        "for each (role, column) pair, without modifying the live policy."
    )

    candidate_text = st.text_area(
        "Candidate policy JSON",
        value="",
        height=240,
        placeholder=(
            'Paste your modified policy JSON here, then click "Compute Diff".\n\n'
            'Tip: copy the current policy from Tab 2, edit it, paste it here, '
            'and see the impact before saving.'
        ),
        key="candidate_policy_text",
    )

    if st.button("Compute Diff", key="compute_diff_btn"):
        if not candidate_text.strip():
            st.warning("Please paste a candidate policy first.")
        else:
            try:
                candidate = json.loads(candidate_text)
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
            else:
                diff = diff_policies(current_policy, candidate, current_catalog)
                if diff.empty:
                    st.success("No access changes between current and candidate policy.")
                else:
                    st.dataframe(diff, use_container_width=True, hide_index=True)
                    n_roles = diff["Role"].nunique()
                    n_cols  = diff["Column"].nunique()
                    n_stricter = (diff["Change"] == "STRICTER").sum()
                    n_looser   = (diff["Change"] == "LOOSER").sum()
                    n_algo     = (diff["Change"] == "ALGO/PARAM").sum()
                    st.markdown(
                        f"**{len(diff)} access changes** across **{n_roles} roles** "
                        f"and **{n_cols} columns**  •  "
                        f"🔒 stricter: {n_stricter}  •  "
                        f"🔓 looser: {n_looser}  •  "
                        f"⚙️ algo/param only: {n_algo}"
                    )
