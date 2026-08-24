import math
import statistics
from typing import List, Tuple, Dict, Any


def zscore(value: float, mean: float, stdev: float, epsilon: float = 1e-6) -> float:
    """Computes standard Z-Score with zero-variance protection."""
    if stdev <= epsilon:
        return 0.0
    return (value - mean) / stdev


def median_absolute_deviation(data: List[float]) -> Tuple[float, float]:
    """
    Computes Median and Median Absolute Deviation (MAD).
    MAD is significantly more robust than standard deviation against extreme outliers
    and benign burst noise, drastically reducing false positives in network telemetry.
    """
    if not data:
        return 0.0, 0.0
    med = statistics.median(data)
    deviations = [abs(x - med) for x in data]
    mad = statistics.median(deviations)
    return med, mad


def modified_zscore(value: float, median: float, mad: float, epsilon: float = 1e-6) -> float:
    """
    Computes Boris Iglewicz and David Hoaglin's Modified Z-Score:
    M_i = 0.6745 * (x_i - median) / MAD
    Scores |M_i| > 3.5 indicate statistically significant anomalies.
    """
    if mad <= epsilon:
        diff = abs(value - median)
        return 0.0 if diff <= epsilon else (diff / (median + epsilon))
    return 0.6745 * (value - median) / mad


def exponential_moving_average(previous_ema: float, current_val: float, alpha: float = 0.2) -> float:
    """
    Computes Adaptive Exponential Moving Average (EMA) for non-stationary baselines.
    alpha: smoothing factor between 0.0 and 1.0 (default: 0.2).
    """
    return alpha * current_val + (1.0 - alpha) * previous_ema


def calculate_shannon_entropy(data: bytes | str) -> float:
    """
    Computes Shannon Entropy (H in bits per symbol) for string or byte buffers.
    Used for detecting DNS tunneling, encoded C2 beacons, and encrypted exfiltration payloads.
    Values > 3.8 in subdomains or non-random headers often indicate encoded data.
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    
    length = len(data)
    if length == 0:
        return 0.0
        
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
        
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
            
    return round(entropy, 4)


def classify_severity(confidence: float, impact: str = "MEDIUM") -> str:
    """
    Determines alert severity based on detection confidence and impact level.
    Returns: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
    """
    if confidence >= 0.85 and impact in ("HIGH", "CRITICAL"):
        return "CRITICAL"
    elif confidence >= 0.70 or impact == "HIGH":
        return "HIGH"
    elif confidence >= 0.50:
        return "MEDIUM"
    elif confidence >= 0.30:
        return "LOW"
    return "INFO"
