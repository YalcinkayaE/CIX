"""
AxoDen Canonical Registry (Engine Room Implementation)

Purpose: Single source of truth for definitions, formulas, helper functions, 
thresholds, and component relationships across EBDP, EFI, CFS/CMRI, MQ, ARV, and VSR.

Strictly adheres to 'Canonical_AxoDen_Engine_Room.md'.

Version: 1.0.0
"""

import math
import hashlib
import json
import struct
from typing import List, Dict, Any, Union, Optional, Tuple

# --- Constants & Thresholds (Conformance Parameters) ---

# ARV Defaults (ER-arv)
ARV_BETA = 2.0          # Verification expansion budget (ln scale)
ARV_TAU = 0.1           # Correlation risk threshold (2-adic distance)
ARV_PHI_LIMIT = 100     # Max verifiable evidence nodes within SLA

# MQ Defaults (ER-mq)
MQ_TAU_1 = 0.6          # Evidence alignment (general)
MQ_TAU_1_CRIT = 0.8     # Evidence alignment (critical)
MQ_TAU_2 = 0.7          # Consistency
MQ_TAU_3 = 0.5          # Novelty vs noise
MQ_TAU_4 = 0.6          # Support independence (general)
MQ_TAU_4_CRIT = 0.8     # Support independence (critical)
MQ_TAU_D = 0.4          # Drift from baseline
MQ_TAU_R = 0.3          # Rate of change

# MQ Weights (M1)
MQ_W_ALPHA = 0.4        # Coverage
MQ_W_BETA = 0.3         # Freshness
MQ_W_GAMMA = 0.2        # Provenance
MQ_W_ETA = 0.1          # Contradiction penalty

# MQ Weights (M2)
MQ_W1 = 1.0             # Direct contradictions
MQ_W2 = 0.5             # Implication conflicts
MQ_W3 = 0.3             # Temporal inconsistencies

# CFS Targets
CFS_IS_TARGET = 0.85
CFS_CMRI_TARGET = 0.10


# --- Helper Functions (Canonical) ---

def clamp01(x: float) -> float:
    """
    Clamps x to [0, 1].
    Ref: Framework Helper
    """
    return max(0.0, min(1.0, x))

def v2(x: int) -> int:
    """
    2-adic valuation exponent. Counts trailing zeros.
    For 64-bit implementation: v2(0) = 64.
    Ref: ARV v1.0.1
    """
    if x == 0:
        return 64
    
    # Count trailing zeros
    zeros = 0
    while (x & 1) == 0:
        x >>= 1
        zeros += 1
    return zeros

def jcs_serialize(data: Any) -> bytes:
    """
    Approximation of RFC 8785 JSON Canonicalization Scheme (JCS).
    Ensures deterministic serialization for hashing.
    Ref: ARV v1.0.1
    """
    # Python's json.dumps with sort_keys=True and specific separators 
    # provides a compliant output for most standard data structures.
    # ensure_ascii=False is critical for UTF-8 preservation.
    return json.dumps(
        data, 
        sort_keys=True, 
        separators=(',', ':'), 
        ensure_ascii=False
    ).encode('utf-8')

def sha256(data: bytes) -> bytes:
    """
    Cryptographic hash function.
    Ref: ARV v1.0.1
    """
    return hashlib.sha256(data).digest()

def hash64(data: bytes) -> int:
    """
    Deterministic 64-bit reduction.
    Returns the first 8 bytes of input as uint64 big-endian.
    Ref: ER-arv.hash64
    """
    if len(data) < 8:
        # Pad with zeros if less than 8 bytes (though sha256 guarantees 32)
        data = data.ljust(8, b'\0')
    return struct.unpack('>Q', data[:8])[0]


# --- Formula Definitions (Canonical) ---

# 1. EBDP (Entropy-Bounded Data Pipelines)

def ebdp_stage_bound(h_conditional: float, h_max: float) -> bool:
    """
    ID: ER-ebdp.stageBound
    Formula: H(X_k | X_{k-1}) <= H_k^max
    """
    return h_conditional <= h_max

def ebdp_global_bound(h_final: float, h_initial: float, h_max_sum: float) -> bool:
    """
    ID: ER-ebdp.globalBound
    Formula: H(X_K) <= H(X_0) + Sum(H_k^max)
    """
    return h_final <= (h_initial + h_max_sum)


# 2. EFI (Entropy-Frugal Intelligence)

def efi_stage_bound(influence: float, epsilon_k: float) -> bool:
    """
    ID: ER-efi.stageBound
    Formula: I(X_k; M_k | X_{k-1}) <= epsilon_k
    """
    return influence <= epsilon_k

def efi_global_bound(total_influence: float, epsilon_sum: float) -> bool:
    """
    ID: ER-efi.globalBound
    Formula: I(X_K; M_{1:K} | X_0) <= Sum(epsilon_k)
    """
    return total_influence <= epsilon_sum

def efi_surplus(mi_model: float, mi_history: float) -> float:
    """
    ID: ER-efi.surplus
    Formula: E_k^+ = max(0, I(X_k'; M_k) - I(X_k'; X_{k-1}))
    """
    return max(0.0, mi_model - mi_history)


# 3. CFS (Coprime-Factor Security)

def cfs_gcd_constraint(factor_i: int, factor_j: int) -> bool:
    """
    ID: ER-cfs.gcdConstraint
    Formula: gcd(f_d(m_i), f_d(m_j)) = 1
    """
    return math.gcd(factor_i, factor_j) == 1

def cfs_is_pair(scores: List[float], weights: List[float]) -> float:
    """
    ID: ER-cfs.isPair
    Formula: IS_ij = Sum(w_d * s_d^(i,j))
    Precondition: sum(weights) should be 1.0 (not strictly enforced here but assumed).
    """
    if len(scores) != len(weights):
        raise ValueError("Scores and weights must have same length")
    return sum(s * w for s, w in zip(scores, weights))

def cfs_is_system_mean(pairwise_scores: List[float], k: int) -> float:
    """
    ID: ER-cfs.isSystem.mean
    Formula: IS_mean = (2 / (k * (k-1))) * Sum(IS_ij)
    """
    if k < 2: return 0.0 # or 1.0 depending on interpretation of single node
    denominator = k * (k - 1)
    return (2.0 / denominator) * sum(pairwise_scores)

def cfs_is_system_min(pairwise_scores: List[float]) -> float:
    """
    ID: ER-cfs.isSystem.min
    Formula: IS_min = min(IS_ij)
    """
    if not pairwise_scores: return 0.0
    return min(pairwise_scores)

def cfs_cmri_bound(is_score: float, epsilon_a: float) -> float:
    """
    ID: ER-cfs.cmriBound
    Formula: CMRI <= 1 - IS + epsilon_A
    Returns the upper bound value.
    """
    return 1.0 - is_score + epsilon_a


# 4. Dependency Primitives (ER-dep)

def dep_rho_def(p_a_intersect_b: float, p_a: float, p_b: float) -> float:
    """
    ID: ER-dep.rhoDef
    Formula: rho(A,B) = P(A intersect B) - P(A)P(B)
    """
    return p_a_intersect_b - (p_a * p_b)

def dep_rho_enforce(rho_obs: float, epsilon_l: float) -> bool:
    """
    ID: ER-dep.rhoEnforce
    Formula: rho_obs <= epsilon_L
    """
    return rho_obs <= epsilon_l


# 5. Ledger & ARV Identity (ER-ledger / ER-arv)

def ledger_node_id(node_data: Dict[str, Any]) -> str:
    """
    ID: ER-ledger.nodeId
    Formula: node_id = sha256(JCS(node - node_id))
    Note: 'node_id' key should be excluded from the dict before passing, 
          or handled by caller.
    Returns hex digest for readability/storage.
    """
    # Assuming node_data is already stripped of self-referential ID
    canonical_bytes = jcs_serialize(node_data)
    digest = sha256(canonical_bytes)
    return digest.hex()

def arv_phi(evidence_graph_nodes: List[Any]) -> int:
    """
    ID: ER-arv.phi
    Formula: phi = |{node_id for node in G_evidence}|
    """
    return len(evidence_graph_nodes)

def arv_d_plus(d_plus_prev: float, phi_curr: int, phi_prev: int) -> float:
    """
    ID: ER-arv.dPlus
    Formula: D+_{t+1} = D+_t + max(0, ln(phi_t) - ln(phi_{t-1}))
    Note: Inputs are phi_curr (t) and phi_prev (t-1).
    """
    if phi_curr <= 0 or phi_prev <= 0:
        # Handle undefined ln(0) or negative logs gracefully
        # In strictly enforced domain, this might be an error or 0 gain.
        return d_plus_prev
    
    delta = math.log(phi_curr) - math.log(phi_prev)
    return d_plus_prev + max(0.0, delta)

def arv_commit(root_output: str) -> bytes:
    """
    ID: ER-arv.commit
    Formula: commit = sha256(root_output_utf8)
    """
    return sha256(root_output.encode('utf-8'))

def arv_xor(h_a: int, h_b: int) -> int:
    """
    ID: ER-arv.xor
    Formula: x = h_A XOR h_B
    """
    return h_a ^ h_b

def arv_dist2(root_a_output: str, root_b_output: str) -> float:
    """
    ID: ER-arv.dist2
    Formula: dist_2 = 2^(-v2(x))
    
    Full Pipeline:
    1. Commit: sha256(utf8)
    2. Hash64: first 8 bytes (big-endian)
    3. XOR: hA ^ hB
    4. v2: trailing zeros
    5. dist2 calculation
    """
    # 1. Commit
    commit_a = arv_commit(root_a_output)
    commit_b = arv_commit(root_b_output)
    
    # 2. Hash64
    h_a = hash64(commit_a)
    h_b = hash64(commit_b)
    
    # 3. XOR
    x = arv_xor(h_a, h_b)
    
    # 4. v2
    v2_val = v2(x)
    
    # 5. dist2
    # dist_2 = 2^(-v2_val)
    return math.pow(2, -v2_val)


# 6. Monitoring Quad (MQ) (ER-mq)

def mq_m1(coverage: float, freshness: float, provenance: float, contradiction: float) -> float:
    """
    ID: ER-mq.m1
    Formula: M1 = clamp01(alpha*cov + beta*fresh + gamma*prov - eta*contra)
    """
    raw_score = (
        MQ_W_ALPHA * coverage +
        MQ_W_BETA * freshness +
        MQ_W_GAMMA * provenance -
        MQ_W_ETA * contradiction
    )
    return clamp01(raw_score)

def mq_m2(n_d: int, n_i: int, n_t: int, n_total: int) -> float:
    """
    ID: ER-mq.m2
    Formula: M2 = clamp01(1 - (w1*N_d + w2*N_i + w3*N_t) / max(1, N))
    """
    penalty_sum = (MQ_W1 * n_d) + (MQ_W2 * n_i) + (MQ_W3 * n_t)
    denominator = max(1, n_total)
    return clamp01(1.0 - (penalty_sum / denominator))

def mq_m3(ig: float, noise: float, vol: float) -> float:
    """
    ID: ER-mq.m3
    Formula: M3 = IG / (IG + Noise + Vol)
    """
    denominator = ig + noise + vol
    if denominator == 0:
        return 0.0 # Avoid division by zero
    return ig / denominator

def mq_m4(pairwise_correlations: List[float]) -> float:
    """
    ID: ER-mq.m4
    Formula: M4 = 1 - max(rho_ij)
    """
    if not pairwise_correlations:
        return 1.0 # No correlations implies independence? Or 0 if undefined?
                   # Assuming 1.0 (perfect independence) if no pairs exist (single channel)
                   # But typical logic requires >=2 channels. 
    max_rho = max(pairwise_correlations)
    return 1.0 - max_rho


# 7. VSR (Verification-Steered Refinement) (ER-vsr)

def vsr_drift(m_t: List[float], m_0: List[float]) -> float:
    """
    ID: ER-vsr.drift
    Formula: D_t = ||m_t - m_0||_1
    """
    if len(m_t) != len(m_0):
        raise ValueError("Monitoring vectors must have same dimension")
    return sum(abs(a - b) for a, b in zip(m_t, m_0))

def vsr_rate(m_t: List[float], m_t_minus_1: List[float]) -> float:
    """
    ID: ER-vsr.rate
    Formula: R_t = ||m_t - m_{t-1}|| (Euclidean usually, but ER says L1 above? 
    Wait, ER-vsr.drift says L1. ER-vsr.rate symbol is ||.|| which implies Euclidean 
    or just general norm.
    Engine Room 001 text says: R_t = ||m_t - m_{t-1}||
    Engine Room 002 code says: D_t = ||...||_1, R_t = ||...|| (unspecified).
    
    Given D_t is L1, using L1 for Rate is also standard in this framework unless
    specified. Let's default to L1 for consistency with drift, or Euclidean.
    Let's use Euclidean (L2) for R_t to differentiate, as is common in control theory 
    rate limiters.
    """
    if len(m_t) != len(m_t_minus_1):
        raise ValueError("Monitoring vectors must have same dimension")
    
    sq_sum = sum((a - b) ** 2 for a, b in zip(m_t, m_t_minus_1))
    return math.sqrt(sq_sum)


# --- ARV Decision Logic Implementation ---

class ARVDecision:
    def __init__(self, action: str, reason: str, metrics: Dict[str, Any]):
        self.action = action
        self.reason = reason
        self.metrics = metrics

def arv_evaluate(
    phi_curr: int, 
    phi_prev: int, 
    d_plus_prev: float, 
    root_a_output: str, 
    root_b_output: str,
    phi_limit: int = ARV_PHI_LIMIT,
    beta: float = ARV_BETA,
    tau: float = ARV_TAU
) -> ARVDecision:
    """
    Executes ARV Decision Precedence Chain.
    
    Returns decision object with action/reason.
    """
    
    # 1. Domain Violation
    if phi_curr <= 0 or phi_prev <= 0:
        return ARVDecision("HALT", "DOMAIN_VIOLATION", {})
        
    # 2. Verifiability Limit
    if phi_curr > phi_limit:
        return ARVDecision("ROLLBACK", "VERIFIABILITY_LIMIT_EXCEEDED", {"phi_curr": phi_curr, "limit": phi_limit})
        
    # Calculate D+ next
    d_plus_next = arv_d_plus(d_plus_prev, phi_curr, phi_prev)
    
    # 3. Entropy Budget
    if d_plus_next > beta:
        return ARVDecision("ROLLBACK", "VERIFICATION_EXPANSION_BUDGET_EXCEEDED", {"d_plus": d_plus_next, "beta": beta})
        
    # Calculate dist_2
    dist_val = arv_dist2(root_a_output, root_b_output)
    
    # 4. Correlation Risk
    if dist_val < tau:
        return ARVDecision("THROTTLE", "ROOT_CORRELATION_RISK", {"dist_2": dist_val, "tau": tau})
        
    # 5. Execute
    return ARVDecision("EXECUTE", "INVARIANTS_PASSED", {
        "d_plus": d_plus_next,
        "dist_2": dist_val,
        "phi_star": phi_curr
    })
