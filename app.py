import streamlit as st
import pandas as pd
import io
import json
import os
import numpy as np
from pathlib import Path
from auth_manager import (
    PERMISSIONS,
    available_roles,
    create_or_update_user,
    delete_user,
    has_permission,
    load_role_permissions,
    load_users,
    login_panel,
    render_user_badge,
    save_role_permissions,
)
from gateway_engine import apply_zero_trust_gateway
from policy_analyzer import render_policy_analyzer_tab

st.set_page_config(page_title="Zero-Trust Data Gateway", layout="wide")

# ==========================================
# Persistent paths
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "shared_data"
DATA_DIR.mkdir(exist_ok=True)

CATALOG_PATH = DATA_DIR / "data_catalog.json"
SHARED_DATA_PATH = DATA_DIR / "shared_data.csv"
POLICY_PATH = DATA_DIR / "policy.json"
AUDIT_LOG_PATH = DATA_DIR / "audit.log"

AVAILABLE_TAGS = [
    "UNTAGGED", "DROP_COLUMN", "PII_Strong",
    "Quasi_PII_Age", "Quasi_PII_Location",
    "Financial", "Public", "Sensitive_Medical"
]

MOCK_POLICY = {
    "roles": {
        "Administrator": {"default_action": "allow", "rules": {}},
        "Professional_Staff": {
            "default_action": "drop",
            "rules": {
                "Sensitive_Medical": {"action": "allow"},
                "PII_Strong": {
                    "action": "mask",
                    "algorithm": "redact",
                    "params": {"mask_char": "*"}
                },
                "Public": {"action": "allow"}
            }
        },
        "General_Analyst": {
            "default_action": "drop",
            "rules": {
                "PII_Strong": {"action": "drop"},
                "Financial": {
                    "action": "mask",
                    "algorithm": "laplace_noise",
                    "params": {"sensitivity": 20000}
                },
                "Quasi_PII_Age": {
                    "action": "mask",
                    "algorithm": "generalize_numeric",
                    "params": {
                        "bins": [0, 30, 40, 50, 60, 100],
                        "labels": ["<30", "30s", "40s", "50s", "60+"]
                    }
                },
                "Quasi_PII_Location": {
                    "action": "mask",
                    "algorithm": "mask_string_tail",
                    "params": {
                        "keep_front_chars": 2,
                        "mask_char": "*"
                    }
                },
                "Public": {"action": "allow"}
            }
        },
        "External_Auditor": {
            "default_action": "drop",
            "rules": {
                "Public": {"action": "allow"},
                "Financial": {
                    "action": "mask",
                    "algorithm": "redact",
                    "params": {"mask_char": "X"}
                }
            }
        }
    }
}

# Login and RBAC gate for the unified app.
# Author: Xinyuan Yu
current_user = login_panel("Zero-Trust Data Gateway")
render_user_badge()
st.title("Zero-Trust Data Gateway")
AVAILABLE_ROLES = available_roles()

if not any(
    has_permission(permission)
    for permission in [
        "portal_access",
        "data_ingest",
        "catalog_manage",
        "gateway_execute",
        "audit_view",
        "system_manage",
    ]
):
    st.error("[ACCESS] Your account does not have permission to use this application.")
    st.stop()


def load_live_policy():
    if POLICY_PATH.exists() and POLICY_PATH.stat().st_size > 0:
        try:
            with open(POLICY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            st.warning(f"[SYSTEM] Failed to load policy.json, using default policy: {e}")
    return MOCK_POLICY


def persist_default_policy_if_missing():
    if not POLICY_PATH.exists() or POLICY_PATH.stat().st_size == 0:
        with open(POLICY_PATH, "w", encoding="utf-8") as f:
            json.dump(MOCK_POLICY, f, indent=4, ensure_ascii=False)


def tags_in_catalog(catalog: dict) -> set:
    return {
        col_meta.get("tag", "UNTAGGED")
        for col_meta in catalog.get("columns", {}).values()
    }


def active_security_mechanisms(catalog: dict) -> list:
    tags_in_use = tags_in_catalog(catalog)
    mechanisms = ["Zero-Trust Access Control (PBAC)"]

    if any(tag.startswith("Quasi_PII") for tag in tags_in_use):
        mechanisms.append("K-Anonymity Suppression")

    if "Financial" in tags_in_use:
        mechanisms.append("Differential Privacy (Laplace Noise)")

    return mechanisms


def default_aggregation_params(df: pd.DataFrame) -> dict:
    numeric_columns = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_columns = df.select_dtypes(include=["object"]).columns.tolist()

    if not numeric_columns:
        return {}

    group_by_cols = []
    if "department" in df.columns:
        group_by_cols = ["department"]
    elif categorical_columns:
        group_by_cols = [categorical_columns[0]]

    target_col = "base_salary" if "base_salary" in df.columns else numeric_columns[0]

    return {
        "group_by_cols": group_by_cols,
        "target_col": target_col,
        "agg_func": "mean",
    }


def auto_profile_column(col_name: str, dtype: str) -> str:
    col_lower = col_name.lower()

    if any(kw in col_lower for kw in ['id', 'name', 'email', 'phone', 'ssn', 'uid']):
        return "PII_Strong"

    if any(kw in col_lower for kw in ['age', 'dob', 'birth']):
        return "Quasi_PII_Age"

    if any(kw in col_lower for kw in ['zip', 'city', 'region', 'state', 'location']):
        return "Quasi_PII_Location"

    if any(kw in col_lower for kw in ['salary', 'price', 'revenue', 'cost', 'amount', 'balance']):
        return "Financial"

    if any(kw in col_lower for kw in ['health', 'disease', 'medical', 'blood', 'diagnosis']):
        return "Sensitive_Medical"

    if any(kw in col_lower for kw in ['dept', 'department', 'role', 'title']):
        return "Public"

    return "UNTAGGED"


def load_catalog_from_disk():
    if not CATALOG_PATH.exists() or CATALOG_PATH.stat().st_size == 0:
        return None

    try:
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"[ERROR] Failed to load saved catalog: {e}")
        return None


def catalog_matches_current_data(catalog: dict, df: pd.DataFrame) -> bool:
    catalog_cols = set(catalog.get("columns", {}).keys())
    df_cols = set(df.columns.astype(str))
    return catalog_cols == df_cols


def catalog_has_untagged(catalog: dict) -> bool:
    return any(
        meta.get("tag") == "UNTAGGED"
        for meta in catalog.get("columns", {}).values()
    )


def get_dataset_signature(file_name: str, df: pd.DataFrame):
    return (
        file_name,
        tuple(df.columns.astype(str)),
        tuple(str(dtype) for dtype in df.dtypes)
    )


# ==========================================
# 1. Data Ingestion
# ==========================================

st.sidebar.header("1. Data Ingestion")
if has_permission("data_ingest"):
    uploaded_file = st.sidebar.file_uploader("Upload any CSV dataset", type=["csv"])
else:
    uploaded_file = None
    st.sidebar.info("Your role cannot upload or replace datasets.")

if uploaded_file is not None:
    st.session_state.use_demo_data = False

if uploaded_file is None:

    if st.session_state.get("use_demo_data", False):
        demo_csv = (
            "emp_id,employee_name,age,zip_code,base_salary,department\n"
            "E01,Alice,25,90210,45000,IT\n"
            "E02,Bob,26,90212,120000,HR\n"
            "E03,Charlie,45,10012,85000,Sales\n"
            "E04,David,45,10012,88000,Sales\n"
            "E05,Eve,150,90210,150000,IT\n"
            "E06,Frank,55,90210,250000,Executive"
        )

        uploaded_file = io.BytesIO(demo_csv.encode("utf-8"))
        uploaded_file.name = "demo_hr_data_with_dp.csv"

    elif SHARED_DATA_PATH.exists() and SHARED_DATA_PATH.stat().st_size > 0:
        uploaded_file = io.BytesIO(SHARED_DATA_PATH.read_bytes())
        uploaded_file.name = "shared_data.csv"
        st.info("[SYSTEM] Loaded persisted dataset from shared_data/shared_data.csv.")

    else:
        st.info(
            "[SYSTEM] Please upload a CSV file in the sidebar to start, "
            "or click the button below to use a Demo Dataset."
        )

        if st.button(
            "Load Demo HR Dataset",
            type="primary",
            disabled=not has_permission("data_ingest")
        ):
            st.session_state.use_demo_data = True
            st.rerun()
        else:
            st.stop()

uploaded_file.seek(0)

try:
    df_raw = pd.read_csv(uploaded_file)

    if df_raw.empty:
        st.error("[ERROR] The CSV file is empty.")
        st.stop()

except pd.errors.EmptyDataError:
    st.error("[ERROR] CSV file is empty or invalid.")
    st.stop()

except Exception as e:
    st.error(f"[ERROR] Failed to read CSV file: {e}")
    st.stop()


# ==========================================
# Restore catalog from disk
# ==========================================

saved_catalog = load_catalog_from_disk()

if "final_catalog_json" in st.session_state:
    if not catalog_matches_current_data(st.session_state.final_catalog_json, df_raw):
        del st.session_state.final_catalog_json

if "final_catalog_json" not in st.session_state:
    if saved_catalog is not None:

        if not catalog_matches_current_data(saved_catalog, df_raw):
            st.warning(
                "[SYSTEM] Existing data_catalog.json does not match the current dataset columns. "
                "Please review tags and save the catalog again."
            )

        elif catalog_has_untagged(saved_catalog):
            st.warning(
                "[SYSTEM] Existing data_catalog.json still contains UNTAGGED fields. "
                "Please resolve tags and save the catalog again."
            )

        else:
            st.session_state.final_catalog_json = saved_catalog


# ==========================================
# Initialize catalog editor
# ==========================================

current_signature = get_dataset_signature(uploaded_file.name, df_raw)

if (
    "catalog_df" not in st.session_state
    or st.session_state.get("current_dataset_signature") != current_signature
):
    st.session_state.current_file = uploaded_file.name
    st.session_state.current_dataset_signature = current_signature

    if "working_catalog_df" in st.session_state:
        del st.session_state.working_catalog_df

    saved_tags = {}

    if saved_catalog is not None and catalog_matches_current_data(saved_catalog, df_raw):
        saved_tags = {
            col: meta.get("tag", "UNTAGGED")
            for col, meta in saved_catalog.get("columns", {}).items()
        }

    catalog_rows = []

    for col, dtype_val in df_raw.dtypes.items():
        catalog_rows.append({
            "Column Name": col,
            "Data Type": str(dtype_val),
            "Ontology Tag": saved_tags.get(
                col,
                auto_profile_column(col, str(dtype_val))
            )
        })

    st.session_state.catalog_df = pd.DataFrame(catalog_rows)


# ==========================================
# Top Navigation Bar (streamlit-option-menu)
# pip install streamlit-option-menu
# ==========================================

from streamlit_option_menu import option_menu

selected_page = option_menu(
    menu_title=None,
    options=[
        "Data Discovery",
        "Gateway Execution",
        "Consumer Portal",
        "Compliance Audit",
        "Policy Analyzer",
        "System Management",
    ],
    icons=[
        "diagram-3-fill",        # Data Discovery
        "shield-lock-fill",      # Gateway Execution
        "person-badge-fill",     # Consumer Portal
        "clipboard2-pulse-fill", # Compliance Audit
        "bug-fill",              # Policy Analyzer
        "gear-wide-connected",   # System Management
    ],
    orientation="horizontal",
    default_index=0,
    styles={
        # 整体导航栏背景
        "container": {
            "padding": "0px",
            "background-color": "#0f1117",
            "border-bottom": "1px solid #2d2d3a",
            "margin-bottom": "1.5rem",
        },
        # 每个 nav 项目的默认样式
        "nav-link": {
            "font-size": "13.5px",
            "font-weight": "500",
            "font-family": "'Inter', 'Segoe UI', sans-serif",
            "color": "#9ca3af",
            "padding": "12px 20px",
            "border-radius": "0px",
            "border-bottom": "2px solid transparent",
            "transition": "all 0.2s ease",
            "--hover-color": "#1e2130",
        },
        # 图标样式
        "icon": {
            "font-size": "15px",
            "margin-right": "6px",
        },
        # 当前选中项样式
        "nav-link-selected": {
            "background-color": "transparent",
            "color": "#6366f1",
            "font-weight": "600",
            "border-bottom": "2px solid #6366f1",
        },
    },
)


# ==========================================
# Page: Data Discovery (Tagging)
# ==========================================

if selected_page == "Data Discovery":
    st.header(f"Metadata Profiling: `{uploaded_file.name}`")

    can_view_discovery = any(
        has_permission(permission)
        for permission in ["data_ingest", "catalog_manage", "policy_view"]
    )

    if not can_view_discovery:
        st.warning("[ACCESS] Your role cannot view data discovery or catalog management.")

    else:

        with st.expander("Preview Raw Data (Top 5 Rows)"):
            st.dataframe(df_raw.head(5), use_container_width=True)

        if (
            "working_catalog_df" not in st.session_state
            or st.session_state.get("current_dataset_signature") != current_signature
        ):
            st.session_state.working_catalog_df = st.session_state.catalog_df.copy()

        st.subheader("Interactive Catalog Editor")
        can_manage_catalog = has_permission("catalog_manage")
        if not can_manage_catalog:
            st.warning("[ACCESS] Your role can view metadata, but cannot modify or save the catalog.")

        def highlight_untagged(row):
            if row["Ontology Tag"] == "UNTAGGED":
                return ["background-color: #ffcccc"] * len(row)
            return [""] * len(row)

        styled_catalog = st.session_state.working_catalog_df.style.apply(
            highlight_untagged,
            axis=1
        )

        edited_catalog_df = st.data_editor(
            styled_catalog,
            column_config={
                "Column Name": st.column_config.Column(disabled=True),
                "Data Type": st.column_config.Column(disabled=True),
                "Ontology Tag": st.column_config.SelectboxColumn(
                    "Ontology Tag",
                    options=AVAILABLE_TAGS,
                    required=True
                )
            },
            hide_index=True,
            use_container_width=True,
            key="data_editor_widget",
            disabled=not can_manage_catalog
        )

        if not edited_catalog_df.equals(st.session_state.working_catalog_df):
            st.session_state.working_catalog_df = edited_catalog_df
            st.rerun()

        if st.button(
            "Save & Generate JSON Catalog",
            type="primary",
            disabled=not can_manage_catalog
        ):
            if "UNTAGGED" in edited_catalog_df["Ontology Tag"].values:
                st.error("[INTERCEPTED] Validation Failed: Unprocessed UNTAGGED fields detected.")

            else:
                final_catalog = {
                    "dataset_id": st.session_state.current_file,
                    "columns": {}
                }

                for _, row in edited_catalog_df.iterrows():
                    final_catalog["columns"][row["Column Name"]] = {
                        "type": row["Data Type"],
                        "tag": row["Ontology Tag"]
                    }

                st.session_state.final_catalog_json = final_catalog

                with open(CATALOG_PATH, "w", encoding="utf-8") as f:
                    json.dump(final_catalog, f, indent=4, ensure_ascii=False)

                df_raw.to_csv(SHARED_DATA_PATH, index=False)

                persist_default_policy_if_missing()

                st.cache_data.clear()

                st.success(
                    "[SUCCESS] Catalog validated and written to disk. "
                    "Portal is now synced."
                )


# ==========================================
# Page: Gateway Execution
# ==========================================

elif selected_page == "Gateway Execution":
    st.header("Gateway Execution View")

    if not has_permission("gateway_execute"):
        st.warning("[ACCESS] Your role cannot execute gateway test queries.")

    elif "final_catalog_json" not in st.session_state:
        st.warning(
            "[WARNING] Gateway locked. "
            "Please resolve tags and save the catalog first."
        )

    else:
        col_left, col_right = st.columns([1, 2])

        with col_left:
            st.subheader("Simulated Identity Injection")

            if has_permission("role_impersonate"):
                selected_role = st.selectbox(
                    "Inject Role:",
                    options=AVAILABLE_ROLES,
                    index=AVAILABLE_ROLES.index(current_user["role"])
                    if current_user["role"] in AVAILABLE_ROLES else 0
                )
            else:
                selected_role = current_user["role"]
                st.text_input("Injected Role:", value=selected_role, disabled=True)

            live_policy = load_live_policy()
            active_role_policy = live_policy.get("roles", {}).get(
                selected_role,
                {"default_action": "drop", "rules": {}}
            )

            if has_permission("policy_view"):
                st.markdown(f"**Active Policy for `{selected_role}`:**")
                st.json(active_role_policy)

        with col_right:
            st.subheader("Query Configuration")

            query_mode = st.radio(
                "Select Query Mode:",
                options=["raw", "aggregated"],
                format_func=lambda x: (
                    "Raw Data Export"
                    if x == "raw"
                    else "Aggregated Statistics"
                ),
                horizontal=True
            )

            agg_params = {}

            if query_mode == "aggregated":
                a_col1, a_col2, a_col3 = st.columns(3)

                num_cols = df_raw.select_dtypes(
                    include=[np.number]
                ).columns.tolist()

                cat_cols = df_raw.select_dtypes(
                    include=["object"]
                ).columns.tolist()

                with a_col1:
                    agg_params["group_by_cols"] = st.multiselect(
                        "Group By:",
                        options=cat_cols,
                        default=[cat_cols[0]] if cat_cols else None
                    )

                with a_col2:
                    agg_params["target_col"] = st.selectbox(
                        "Calculate on:",
                        options=num_cols,
                        index=0 if num_cols else None
                    )

                with a_col3:
                    agg_params["agg_func"] = st.selectbox(
                        "Function:",
                        options=["mean", "sum", "max", "min", "count"]
                    )

            st.markdown("---")

            st.subheader("Global Privacy Parameters")

            tags_in_use = tags_in_catalog(st.session_state.final_catalog_json)

            needs_k_anon = any(
                tag.startswith("Quasi_PII")
                for tag in tags_in_use
            )

            needs_dp = "Financial" in tags_in_use

            selected_k = 2
            selected_epsilon = 1.0

            if needs_k_anon or needs_dp:
                p_col1, p_col2 = st.columns(2)

                if needs_k_anon:
                    with p_col1:
                        st.markdown("**K-Anonymity (Quasi-Identifiers)**")
                        selected_k = st.slider(
                            "Set K-Anonymity Threshold:",
                            1,
                            10,
                            2
                        )

                if needs_dp:
                    with p_col2:
                        st.markdown("**Differential Privacy (Financials)**")
                        selected_epsilon = st.select_slider(
                            "Set Privacy Budget (epsilon):",
                            options=[0.1, 0.5, 1.0, 5.0, 10.0],
                            value=1.0
                        )

            else:
                st.info(
                    "[SYSTEM] No Quasi_PII or Financial tags detected in current catalog. "
                    "Advanced privacy sliders are hidden."
                )

            if st.button(
                "Execute Zero-Trust Query",
                type="primary",
                key="execute_query_btn"
            ):
                admin_audit_context = {
                    "username": current_user["username"],
                    "role": selected_role,
                    "purpose": "Admin_Testing",
                    "query_type": query_mode
                }

                df_result, trace_log = apply_zero_trust_gateway(
                    df=df_raw.copy(),
                    catalog=st.session_state.final_catalog_json,
                    policy=active_role_policy,
                    audit_context=admin_audit_context,
                    k_value=selected_k,
                    epsilon_value=selected_epsilon,
                    query_type=query_mode,
                    agg_params=agg_params
                )

                st.subheader("Sanitized Output Dataset")
                st.dataframe(df_result, use_container_width=True)

                st.subheader("Governance Trace Log")

                for log_entry in trace_log:
                    if "[ALLOW]" in log_entry:
                        st.info(log_entry)

                    elif "[MASK]" in log_entry or "[GLOBAL-POLICY]" in log_entry:
                        st.warning(log_entry)

                    elif "[ROUTING]" in log_entry:
                        st.success(log_entry)

                    elif "[DROP]" in log_entry or "[FAIL-SAFE]" in log_entry:
                        st.error(log_entry)

                    else:
                        st.markdown(f"`{log_entry}`")


# ==========================================
# Page: Consumer Portal
# ==========================================

elif selected_page == "Consumer Portal":
    st.header("Data Consumer Portal")
    st.caption(f"Authenticated user: {current_user['display_name']} ({current_user['username']})")

    if not has_permission("portal_access"):
        st.warning("[ACCESS] Your role cannot use the Consumer Portal.")

    elif "final_catalog_json" not in st.session_state:
        st.warning(
            "[WARNING] No active catalog detected. "
            "Please ask a data steward to complete configuration first."
        )

    else:
        consumer_col, output_col = st.columns([1, 2])

        with consumer_col:
            st.subheader("Access Context")
            selected_role = current_user["role"]
            st.text_input("Requesting Role:", value=selected_role, disabled=True)
            selected_purpose = st.selectbox(
                "Access Purpose:",
                ["Academic_Research", "Internal_Audit", "Marketing_Overview"],
                key="consumer_access_purpose"
            )
            enable_debug = st.checkbox(
                "Enable Debug Mode",
                value=False,
                help="Display backend routing and governance trace logs.",
                key="consumer_debug_mode"
            )

            st.markdown("**Active Security Mechanisms for Current Dataset:**")
            for mechanism in active_security_mechanisms(st.session_state.final_catalog_json):
                st.markdown(f"- `{mechanism}`")

            submit_request = st.button(
                "Request Data Access",
                type="primary",
                use_container_width=True,
                key="consumer_request_access"
            )

        with output_col:
            if not submit_request:
                st.info("[SYSTEM] Portal is connected. Define your context and request data.")

            else:
                query_mode = (
                    "aggregated"
                    if selected_purpose in ["Marketing_Overview", "Academic_Research"]
                    else "raw"
                )
                agg_params = default_aggregation_params(df_raw) if query_mode == "aggregated" else None

                if query_mode == "aggregated" and not agg_params:
                    st.error(
                        "Access Denied: Aggregated access requires at least one numeric column."
                    )

                else:
                    live_policy = load_live_policy()
                    current_policy = live_policy.get("roles", {}).get(
                        selected_role,
                        {"default_action": "drop", "rules": {}}
                    )
                    audit_context = {
                        "username": current_user["username"],
                        "role": selected_role,
                        "purpose": selected_purpose,
                        "query_type": query_mode,
                        "query_filter": "Full Scan",
                    }

                    with st.spinner("Processing through Zero-Trust Gateway..."):
                        df_result, trace_log = apply_zero_trust_gateway(
                            df=df_raw.copy(),
                            catalog=st.session_state.final_catalog_json,
                            policy=current_policy,
                            audit_context=audit_context,
                            k_value=2,
                            epsilon_value=1.0,
                            query_type=query_mode,
                            agg_params=agg_params,
                        )

                    if not df_result.empty:
                        st.success(f"Request evaluated and authorized for {selected_purpose}.")
                        st.subheader("Authorized Data Output")
                        st.dataframe(df_result, use_container_width=True, hide_index=True)
                    else:
                        st.error(
                            "Access Denied: Request intercepted by Zero-Trust Policy Engine "
                            "or no data matched filters."
                        )

                    if enable_debug:
                        st.divider()
                        with st.expander("Governance Trace Log (Debug Mode)", expanded=True):
                            for log_entry in trace_log:
                                if "[ALLOW]" in log_entry or "[ROUTING]" in log_entry:
                                    st.success(log_entry)
                                elif "[MASK]" in log_entry or "[GLOBAL-POLICY]" in log_entry:
                                    st.warning(log_entry)
                                elif "[DROP]" in log_entry or "[FAIL-SAFE]" in log_entry:
                                    st.error(log_entry)
                                elif "[INTENT]" in log_entry or "[RESULT]" in log_entry:
                                    st.info(log_entry)
                                else:
                                    st.markdown(f"`{log_entry}`")


# ==========================================
# Page: Compliance Audit
# ==========================================

elif selected_page == "Compliance Audit":
    st.header("Platform Compliance & Audit Center")
    st.caption(
        "All user queries, policy evaluations, and masking actions "
        "are cryptographically logged and immutable."
    )

    if not has_permission("audit_view"):
        st.warning("[ACCESS] Your role cannot view compliance audit logs.")

    else:
        audit_file_path = AUDIT_LOG_PATH

        col_title, col_btn = st.columns([8, 2])

        with col_btn:
            if st.button(
                "Clear Audit History",
                type="secondary",
                use_container_width=True,
                disabled=not has_permission("audit_clear")
            ):
                if os.path.exists(audit_file_path):
                    os.remove(audit_file_path)

                st.success("Audit history successfully cleared.")
                st.rerun()

        if os.path.exists(audit_file_path) and os.path.getsize(audit_file_path) > 0:
            logs = []

            with open(audit_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        logs.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue

            if logs:
                total_queries = len(logs)

                interception_alerts = sum(
                    1 for log in logs
                    if any(
                        "[DROP]" in trace or "[FAIL-SAFE]" in trace
                        for trace in log.get("execution_trace", [])
                    )
                )

                st.subheader("Security Trend Analysis")

                m_col1, m_col2, m_col3 = st.columns(3)

                m_col1.metric("Total Compliance Queries", total_queries)
                m_col2.metric("Security Interception Alerts", interception_alerts)

                total_rows = sum(
                    log.get("rows_returned", 0)
                    for log in logs
                )

                m_col3.metric("Total Rows Transferred", total_rows)

                st.markdown("---")
                st.subheader("Live Audit Trail")

                audit_df = pd.DataFrame(logs)

                audit_df["timestamp"] = pd.to_datetime(
                    audit_df["timestamp"]
                )

                audit_df = audit_df.sort_values(
                    by="timestamp",
                    ascending=False
                ).reset_index(drop=True)

                audit_df["execution_trace"] = audit_df["execution_trace"].apply(
                    lambda x: "\n".join(x) if isinstance(x, list) else x
                )

                st.dataframe(
                    audit_df,
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "timestamp": st.column_config.DatetimeColumn(
                            "Timestamp",
                            format="YYYY-MM-DD HH:mm:ss"
                        ),
                        "username": st.column_config.TextColumn("User"),
                        "role": st.column_config.TextColumn("Role"),
                        "purpose": st.column_config.TextColumn("Purpose"),
                        "query_filter": st.column_config.TextColumn(
                            "Query Intent (Filter)"
                        ),
                        "rows_returned": st.column_config.NumberColumn(
                            "Rows Output"
                        ),
                        "execution_trace": st.column_config.TextColumn(
                            "Execution Trace (Logs)",
                            width="large"
                        )
                    }
                )

            else:
                st.info("[SYSTEM] No valid audit logs found in the file.")

        else:
            st.warning(
                "[SYSTEM] Audit log file not detected or empty. "
                "Awaiting system initialization..."
            )


# ==========================================
# Page: System Management
# ==========================================

# ==========================================
# Page: Policy Analyzer
# ==========================================

elif selected_page == "Policy Analyzer":
    if not has_permission("policy_view"):
        st.warning("[ACCESS] Your role cannot access the Policy Analyzer.")
    else:
        live_policy = load_live_policy()
        current_catalog = st.session_state.get("final_catalog_json", {})
        render_policy_analyzer_tab(
            current_policy=live_policy,
            current_catalog=current_catalog,
            audit_log_path=str(AUDIT_LOG_PATH),
        )


elif selected_page == "System Management":
    st.header("System Management")

    if not has_permission("system_manage"):
        st.warning("[ACCESS] Your role cannot manage users, roles, or permission groups.")

    else:
        role_config = load_role_permissions()
        users = load_users()

        sys_tab1, sys_tab2, sys_tab3 = st.tabs([
            "Users",
            "Roles",
            "Permission Groups"
        ])

        with sys_tab1:
            st.subheader("User Directory")
            user_rows = [
                {
                    "Username": user.get("username", ""),
                    "Display Name": user.get("display_name", ""),
                    "Role": user.get("role", ""),
                    "Active": user.get("active", True),
                    "Created At": user.get("created_at", ""),
                }
                for user in users
            ]
            st.dataframe(pd.DataFrame(user_rows), use_container_width=True, hide_index=True)

            st.subheader("Create or Update User")
            usernames = [user.get("username", "") for user in users]
            selected_user = st.selectbox("Select user", ["<new user>"] + usernames)
            existing_user = next(
                (user for user in users if user.get("username") == selected_user),
                None
            )

            with st.form("user_admin_form"):
                username = st.text_input(
                    "Username",
                    value="" if existing_user is None else existing_user.get("username", ""),
                    disabled=existing_user is not None
                )
                display_name = st.text_input(
                    "Display Name",
                    value="" if existing_user is None else existing_user.get("display_name", "")
                )
                role = st.selectbox(
                    "Role",
                    options=AVAILABLE_ROLES,
                    index=AVAILABLE_ROLES.index(existing_user.get("role"))
                    if existing_user and existing_user.get("role") in AVAILABLE_ROLES
                    else 0
                )
                active = st.checkbox(
                    "Active",
                    value=True if existing_user is None else existing_user.get("active", True)
                )
                password = st.text_input(
                    "Password",
                    type="password",
                    help="Required for new users. Leave blank to keep the current password."
                )
                submitted_user = st.form_submit_button("Save User", type="primary")

            if submitted_user:
                try:
                    create_or_update_user(username or selected_user, display_name, role, active, password)
                    st.success("User saved.")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))

            if existing_user and selected_user != current_user["username"]:
                if st.button("Delete Selected User", type="secondary"):
                    delete_user(selected_user)
                    st.success("User deleted.")
                    st.rerun()

        with sys_tab2:
            st.subheader("Role to Permission Group Mapping")
            role_rows = []
            for role_name, meta in role_config.get("roles", {}).items():
                role_rows.append({
                    "Role": role_name,
                    "Permission Group": meta.get("permission_group", ""),
                    "Description": meta.get("description", ""),
                })

            edited_roles = st.data_editor(
                pd.DataFrame(role_rows),
                hide_index=True,
                use_container_width=True,
                column_config={
                    "Role": st.column_config.Column(disabled=True),
                    "Permission Group": st.column_config.SelectboxColumn(
                        "Permission Group",
                        options=list(role_config.get("permission_groups", {}).keys()),
                        required=True
                    ),
                    "Description": st.column_config.TextColumn("Description"),
                },
                key="role_permission_editor"
            )

            if st.button("Save Role Mapping", type="primary"):
                for _, row in edited_roles.iterrows():
                    role_config["roles"][row["Role"]] = {
                        "permission_group": row["Permission Group"],
                        "description": row["Description"],
                    }
                save_role_permissions(role_config)
                st.success("Role mapping saved.")
                st.rerun()

        with sys_tab3:
            st.subheader("Permission Groups")
            valid_permissions = set(PERMISSIONS.keys())
            group_rows = []
            for group_name, permissions in role_config.get("permission_groups", {}).items():
                group_rows.append({
                    "Group": group_name,
                    "Permissions": ", ".join(permissions),
                })

            edited_groups = st.data_editor(
                pd.DataFrame(group_rows),
                hide_index=True,
                use_container_width=True,
                num_rows="dynamic",
                column_config={
                    "Group": st.column_config.TextColumn("Group", required=True),
                    "Permissions": st.column_config.TextColumn(
                        "Permissions",
                        help="Comma-separated permission keys."
                    ),
                },
                key="permission_group_editor"
            )

            st.caption("Available permission keys: " + ", ".join(PERMISSIONS.keys()))

            if st.button("Save Permission Groups", type="primary"):
                next_groups = {}
                invalid_permissions = []
                for _, row in edited_groups.iterrows():
                    group_name = str(row["Group"]).strip()
                    permissions = [
                        permission.strip()
                        for permission in str(row["Permissions"]).split(",")
                        if permission.strip()
                    ]
                    invalid_permissions.extend(
                        permission
                        for permission in permissions
                        if permission not in valid_permissions
                    )
                    if group_name:
                        next_groups[group_name] = permissions

                if invalid_permissions:
                    st.error("Invalid permissions: " + ", ".join(sorted(set(invalid_permissions))))
                else:
                    role_config["permission_groups"] = next_groups
                    save_role_permissions(role_config)
                    st.success("Permission groups saved.")
                    st.rerun()
