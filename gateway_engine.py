"""
gateway_engine.py  —  Zero-Trust Data Gateway · Core Engine
============================================================
版本历史
--------
v1  原始网关引擎（masking algorithms + k-anonymity + audit log）
v2  集成 auth_manager 身份验证模块（用户名写入审计日志）
v3  [当前] 合并版本：
      - 保留 v2 的 authenticated user audit attribution
      - 集成 policy_analyzer 的静态分析能力（可选的启动时策略预检）
      - 新增 GatewayContext dataclass，统一 audit_context 构建方式
      - 新增 validate_policy_on_startup() 工厂函数，供 app.py 在应用
        初始化阶段调用，将策略分析结果写入 session 或日志
      - _write_audit_log_async 现在支持 username 字段（auth_manager 集成）
      - 所有公共接口保持向后兼容，app.py / app_portal.py 无需改动

合并说明
--------
分叉点：两份 gateway_engine.py 的唯一差异在 _write_audit_log_async：
  - 旧版（app_portal.py 配套）：不写 username 字段
  - 新版（app.py 配套）：      写 username 字段（来自 auth_manager）
合并策略：以新版为准，username 默认回退为 "UNKNOWN"，保持向后兼容。

policy_analyzer 集成：
  - gateway_engine 不直接 import policy_analyzer（避免循环依赖）
  - 而是暴露 validate_policy_on_startup() 接口，由 app.py 按需调用
  - 详见文件末尾的「Policy Pre-flight」章节
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd


# =============================================================================
# GatewayContext  —  统一的审计上下文构建器
# =============================================================================

@dataclass
class GatewayContext:
    """
    统一封装一次网关调用的身份 + 意图信息。

    用法（在 app.py 中替换原来的裸 dict）：
        ctx = GatewayContext(
            username=current_user["username"],
            role=selected_role,
            purpose="Internal_Audit",
            query_type="raw",
            query_filter="dept=HR",
        )
        df_result, trace = apply_zero_trust_gateway(..., audit_context=ctx.to_dict())

    或者直接传 GatewayContext 实例（apply_zero_trust_gateway 已做兼容处理）。
    """
    role:         str = "UNKNOWN"
    purpose:      str = "UNKNOWN"
    query_type:   str = "raw"
    query_filter: str = "Full Scan"
    # auth_manager 集成字段 —— 由 login_panel() 返回的 user dict 填充
    username:     str = "UNKNOWN"
    # 运行时由引擎回填，调用方无需设置
    rows_returned: int = field(default=0, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GatewayContext":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


# =============================================================================
# Algorithm Helper Functions
# =============================================================================

def generalize_numeric_safe(series: pd.Series, params: dict) -> pd.Series:
    result = pd.cut(series, bins=params["bins"], labels=params["labels"])
    if result.isna().any():
        result = result.cat.add_categories(["OUT_OF_BOUNDS"])
        result = result.fillna("OUT_OF_BOUNDS")
    return result


def mask_string_tail(series: pd.Series, params: dict) -> pd.Series:
    keep = params.get("keep_front_chars", 3)
    char = params.get("mask_char", "*")
    return series.astype(str).apply(
        lambda x: x[:keep] + char * max(0, len(x) - keep)
    )


def inject_laplace_noise(series: pd.Series, params: dict) -> pd.Series:
    sensitivity = params.get("sensitivity", 10000)
    epsilon = params.get("epsilon", 1.0)
    epsilon = max(epsilon, 0.01)
    scale = sensitivity / epsilon
    noise = np.random.laplace(loc=0.0, scale=scale, size=len(series))
    noisy_series = series + noise
    return noisy_series.clip(lower=0).round(2)


MASKING_ALGORITHMS: Dict[str, Any] = {
    "generalize_numeric": generalize_numeric_safe,
    "mask_string_tail":   mask_string_tail,
    "laplace_noise":      inject_laplace_noise,
    "hash_string": lambda series, params: series.apply(
        lambda x: hashlib.sha256(str(x).encode()).hexdigest()[: params.get("length", 8)]
    ),
    "redact": lambda series, params: series.apply(
        lambda x: params.get("mask_char", "*") * len(str(x))
    ),
}


# =============================================================================
# Phase 2 & 3 Helpers
# =============================================================================

def enforce_k_anonymity(
    df: pd.DataFrame,
    catalog: Dict[str, Any],
    k_value: int,
) -> Tuple[pd.DataFrame, str]:
    """
    对结果集执行全局 K-匿名性检验：
    将所有 Quasi_PII 标记列作为准标识符，抑制等价类大小 < k 的行。
    """
    qi_cols = [
        col
        for col, meta in catalog.get("columns", {}).items()
        if str(meta.get("tag", "")).startswith("Quasi_PII") and col in df.columns
    ]
    if not qi_cols:
        return df, "[INFO] No 'Quasi_PII' variant columns detected. Global K-Anonymity check skipped."

    original_row_count = len(df)
    group_counts = (
        df.groupby(qi_cols, observed=False, dropna=False)
        .size()
        .reset_index(name="_qi_count")
    )
    df_merged = df.merge(group_counts, on=qi_cols, how="left")
    df_k_anonymous = df_merged[df_merged["_qi_count"] >= k_value].copy()
    df_k_anonymous = df_k_anonymous.drop(columns=["_qi_count"])

    suppressed_count = original_row_count - len(df_k_anonymous)
    log_msg = f"[GLOBAL-POLICY] Enforced K-Anonymity (k={k_value}). Suppressed {suppressed_count} rows."
    return df_k_anonymous, log_msg


def secure_aggregation(
    df: pd.DataFrame,
    group_by_cols: List[str],
    target_col: str,
    agg_func: str = "mean",
    min_k: int = 3,
) -> Tuple[pd.DataFrame, str]:
    """
    安全聚合封区（Statistical Enclave）：
    对微组（headcount < min_k）进行抑制，防止差分攻击。
    """
    if not group_by_cols or target_col not in df.columns:
        return pd.DataFrame(), "[FAIL-SAFE] Invalid aggregation parameters provided."

    agg_df = (
        df.groupby(group_by_cols, observed=False)
        .agg(
            Result=(target_col, agg_func),
            Headcount=(target_col, "count"),
        )
        .reset_index()
    )

    result_name = f"{target_col}_{agg_func}"
    agg_df = agg_df.rename(columns={"Result": result_name})

    safe_agg_df = agg_df[agg_df["Headcount"] >= min_k].copy()
    suppressed_groups = len(agg_df) - len(safe_agg_df)
    log_msg = (
        f"[AGGREGATION-SAFE] Calculated {agg_func.upper()} of '{target_col}'. "
        f"Suppressed {suppressed_groups} micro-groups (< {min_k} individuals)."
    )

    safe_agg_df = safe_agg_df.drop(columns=["Headcount"])
    return safe_agg_df, log_msg


# =============================================================================
# Core Audit Logging（集成 auth_manager 的 username 字段）
# =============================================================================

def _read_last_hash(audit_path: str) -> str:
    """
    反向扫描审计文件，返回最后一条有效日志的 hash 值。
    若文件不存在、为空或全部行均无 hash 字段，返回 'GENESIS'。
    """
    if not os.path.exists(audit_path) or os.path.getsize(audit_path) == 0:
        return "GENESIS"

    try:
        with open(audit_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b""
            while size > 0:
                step = min(block, size)
                size -= step
                f.seek(size)
                data = f.read(step) + data
                if b"\n" in data:
                    break

        lines = data.splitlines()
        for raw in reversed(lines):
            try:
                obj = json.loads(raw.decode("utf-8"))
                if isinstance(obj, dict) and "hash" in obj:
                    return str(obj["hash"])
            except Exception:
                continue
    except Exception:
        pass

    return "GENESIS"


def _compute_entry_hash(prev_hash: str, entry_without_hash: dict) -> str:
    canonical = json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":"))
    payload = (prev_hash + canonical).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _write_audit_log_async(context: dict, trace_log: list) -> None:
    """
    异步写入单条审计日志（链式哈希结构）。

    集成说明（auth_manager）：
      context 中现在包含 "username" 键，由 GatewayContext 或 app.py 的
      audit_context dict 注入。若调用方未提供（如旧版 app_portal.py），
      默认回退为 "UNKNOWN"，保持向后兼容。
    """
    audit_path = "shared_data/audit.log"

    # ── 构建日志条目 ──────────────────────────────────────────────────────
    entry = {
        "timestamp":       datetime.utcnow().isoformat() + "Z",
        # auth_manager 集成：记录已认证用户名（向后兼容回退为 UNKNOWN）
        "username":        context.get("username", "UNKNOWN"),
        "role":            context.get("role", "UNKNOWN"),
        "purpose":         context.get("purpose", "UNKNOWN"),
        "query_type":      context.get("query_type", "raw"),
        "query_filter":    context.get("query_filter", "Full Scan"),
        "rows_returned":   context.get("rows_returned", 0),
        "execution_trace": trace_log,
    }

    prev_hash = _read_last_hash(audit_path)
    entry_with_prev = dict(entry)
    entry_with_prev["prev_hash"] = prev_hash

    entry_hash = _compute_entry_hash(prev_hash, entry_with_prev)
    entry_with_prev["hash"] = entry_hash

    try:
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_with_prev) + "\n")
    except Exception as e:
        print(f"[AUDIT] Failed to write audit log: {e}")


# =============================================================================
# Core Dispatcher
# =============================================================================

def apply_zero_trust_gateway(
    df: pd.DataFrame,
    catalog: Dict[str, Any],
    policy: Dict[str, Any],
    audit_context: "Dict[str, Any] | GatewayContext",
    k_value: int = 2,
    epsilon_value: float = 1.0,
    query_type: str = "raw",
    agg_params: Optional[dict] = None,
) -> Tuple[pd.DataFrame, List[str]]:
    """
    零信任数据网关核心分发器。

    Parameters
    ----------
    df            : 原始 DataFrame（调用方传入 .copy()）
    catalog       : 数据目录（columns → tag/type 映射）
    policy        : 单个角色的策略字典 {default_action, rules}
    audit_context : 审计上下文，接受 dict 或 GatewayContext 实例
    k_value       : K-匿名性阈值
    epsilon_value : 差分隐私预算 ε
    query_type    : "raw" | "aggregated"
    agg_params    : aggregated 模式下的聚合参数

    Returns
    -------
    (result_df, trace_log)
    """
    # ── 统一 audit_context 为 dict ────────────────────────────────────────
    if isinstance(audit_context, GatewayContext):
        audit_context = audit_context.to_dict()

    trace_log: List[str] = []

    # 1. 捕获用户意图
    query_filter = audit_context.get("query_filter", "Full Scan")
    trace_log.append(f"[INTENT] Requesting access. Filter applied: {query_filter}")

    # ── ROUTE A: Statistical Enclave（聚合统计封区）──────────────────────
    if query_type == "aggregated" and agg_params:
        trace_log.append("[ROUTING] 'Aggregated' mode detected. Entering Statistical Enclave.")
        group_by_cols = agg_params.get("group_by_cols", [])
        target_col    = agg_params.get("target_col", "")
        agg_func      = agg_params.get("agg_func", "mean")

        safe_agg_df, agg_log = secure_aggregation(
            df, group_by_cols, target_col, agg_func, min_k=k_value
        )
        trace_log.append(agg_log)
        trace_log.append(f"[RESULT] Execution complete. Returned {len(safe_agg_df)} aggregated rows.")

        audit_context["rows_returned"] = len(safe_agg_df)
        threading.Thread(
            target=_write_audit_log_async, args=(audit_context, trace_log), daemon=True
        ).start()
        return safe_agg_df, trace_log

    # ── ROUTE B: Standard Micro-Masking（逐列脱敏 + DP）─────────────────
    trace_log.append("[ROUTING] 'Raw Data' mode detected. Executing micro-masking with DP capabilities.")
    default_action = policy.get("default_action", "drop")
    result_df = pd.DataFrame()

    for col in df.columns:
        col_meta = catalog.get("columns", {}).get(col, {})
        tag      = col_meta.get("tag", "UNTAGGED")
        rule     = policy.get("rules", {}).get(tag, {"action": default_action})
        action   = rule.get("action")

        if action == "allow":
            result_df[col] = df[col]
            trace_log.append(f"[ALLOW] Column '{col}' (Tag: {tag}) -> Plaintext access granted.")

        elif action == "mask":
            algo_name = rule.get("algorithm")
            params    = rule.get("params", {}).copy()

            # 将全局 epsilon 注入 laplace_noise 算法参数
            if algo_name == "laplace_noise":
                params["epsilon"] = epsilon_value

            if algo_name in MASKING_ALGORITHMS:
                try:
                    result_df[col] = MASKING_ALGORITHMS[algo_name](df[col], params)
                    trace_log.append(f"[MASK] Column '{col}' (Tag: {tag}) -> Applied '{algo_name}'.")
                except Exception as exc:
                    trace_log.append(
                        f"[FAIL-SAFE] Column '{col}' -> Algo '{algo_name}' failed. "
                        f"Dropped. Reason: {exc}"
                    )
            else:
                trace_log.append(
                    f"[FAIL-SAFE] Column '{col}' -> Unregistered algorithm '{algo_name}'. Dropped."
                )

        else:  # drop（含 default）
            trace_log.append(f"[DROP] Column '{col}' (Tag: {tag}) -> Access denied.")

    # 全局 K-匿名性后置检验
    result_df, k_log = enforce_k_anonymity(result_df, catalog, k_value)
    trace_log.append(k_log)

    # 2. 捕获最终结果
    trace_log.append(
        f"[RESULT] Execution complete. Returned {len(result_df)} rows. "
        f"Columns accessible: {list(result_df.columns)}"
    )
    audit_context["rows_returned"] = len(result_df)

    threading.Thread(
        target=_write_audit_log_async, args=(audit_context, trace_log), daemon=True
    ).start()

    return result_df, trace_log


# =============================================================================
# Policy Pre-flight（policy_analyzer 集成入口）
# =============================================================================
#
# 设计原则：gateway_engine 不直接 import policy_analyzer，
# 以避免在无 Streamlit 环境（如单元测试、CLI）中引入不必要依赖。
# 而是提供一个工厂函数，由调用方（app.py）在应用初始化时主动调用。
#
# 在 app.py 中的接入方式：
#
#   from gateway_engine import run_policy_preflight
#   from policy_analyzer import run_full_analysis, render_policy_analyzer_tab
#
#   # 应用启动后（已加载 policy / catalog），执行一次预检：
#   preflight_result = run_policy_preflight(live_policy, catalog, str(AUDIT_LOG_PATH))
#   if preflight_result["summary"]["critical"] > 0:
#       st.sidebar.error(f"⚠️ {preflight_result['summary']['critical']} critical policy issues detected!")
#
# =============================================================================

def run_policy_preflight(
    policy: Dict[str, Any],
    catalog: Dict[str, Any],
    audit_log_path: str,
    *,
    analyzer_fn: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """
    在网关启动/热更新时执行一次策略静态分析预检。

    Parameters
    ----------
    policy         : 当前活跃策略（来自 policy.json）
    catalog        : 当前数据目录（来自 data_catalog.json）
    audit_log_path : 审计日志路径
    analyzer_fn    : 注入 policy_analyzer.run_full_analysis 函数。
                     若为 None，则尝试自动 import；若导入失败则跳过预检。

    Returns
    -------
    run_full_analysis() 的返回值 dict，或 None（当 analyzer 不可用时）。
    """
    fn = analyzer_fn

    if fn is None:
        try:
            from policy_analyzer import run_full_analysis  # type: ignore
            fn = run_full_analysis
        except ImportError:
            # policy_analyzer 未安装或不在 PYTHONPATH，静默跳过
            return None

    try:
        result = fn(policy, catalog, audit_log_path)
        # 将预检摘要写入控制台，便于容器日志监控
        summary = result.get("summary", {})
        print(
            f"[PREFLIGHT] Policy analysis complete — "
            f"critical={summary.get('critical', 0)}, "
            f"warning={summary.get('warning', 0)}, "
            f"info={summary.get('info', 0)}"
        )
        return result
    except Exception as exc:
        print(f"[PREFLIGHT] Policy analysis failed: {exc}")
        return None
