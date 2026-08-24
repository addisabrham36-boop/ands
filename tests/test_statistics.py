import math
from core.statistics import (
    zscore,
    median_absolute_deviation,
    modified_zscore,
    exponential_moving_average,
    calculate_shannon_entropy,
    classify_severity
)


def test_standard_zscore():
    assert zscore(100, 100, 10) == 0.0
    assert zscore(130, 100, 10) == 3.0
    assert zscore(100, 100, 0.0) == 0.0


def test_median_absolute_deviation_robustness():
    # Regular dataset with one massive outlier
    data = [10, 11, 10, 12, 10, 11, 10, 12, 10, 500]
    med, mad = median_absolute_deviation(data)
    
    assert med in (10, 10.5, 11)
    assert mad <= 2.0  # MAD is not inflated by the 500 spike!


def test_modified_zscore():
    data = [10, 11, 10, 12, 10, 11, 10, 12, 10]
    med, mad = median_absolute_deviation(data)
    
    # Normal point should have low modified z-score
    mod_z_norm = modified_zscore(11, med, mad)
    assert abs(mod_z_norm) < 2.0
    
    # Extreme spike should have high modified z-score
    mod_z_spike = modified_zscore(100, med, mad)
    assert mod_z_spike > 5.0


def test_exponential_moving_average():
    prev_ema = 10.0
    current = 20.0
    alpha = 0.2
    new_ema = exponential_moving_average(prev_ema, current, alpha)
    assert abs(new_ema - 12.0) < 1e-5


def test_shannon_entropy():
    # Low entropy repetitive string
    low_ent = calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    # Normal text
    norm_ent = calculate_shannon_entropy("example.com")
    assert norm_ent < 3.5

    # Base64 high entropy tunneling payload
    tunnel_payload = "dGVzdC1kbnMtdHVubmVsLWV4ZmlsdHJhdGlvbg=="
    high_ent = calculate_shannon_entropy(tunnel_payload)
    assert high_ent > 3.6


def test_severity_classification():
    assert classify_severity(0.90, "CRITICAL") == "CRITICAL"
    assert classify_severity(0.75, "HIGH") == "HIGH"
    assert classify_severity(0.55, "MEDIUM") == "MEDIUM"
    assert classify_severity(0.35, "LOW") == "LOW"
    assert classify_severity(0.10, "INFO") == "INFO"
