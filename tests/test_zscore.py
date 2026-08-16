import statistics


def zscore(value, mean, stdev):
    if stdev == 0:
        return 0.0
    return (value - mean) / stdev


def test_zscore_flags_spike():
    normal_rates = [100, 102, 98, 101, 99, 100, 103, 97]
    spike = 400

    mean_rate = statistics.mean(normal_rates)
    stdev_rate = statistics.stdev(normal_rates)

    z = zscore(spike, mean_rate, stdev_rate)
    assert z >= 3.0, f"Expected spike to be flagged, got z={z}"


def test_zscore_ignores_normal_variation():
    normal_rates = [100, 102, 98, 101, 99, 100, 103, 97]
    typical_value = 101

    mean_rate = statistics.mean(normal_rates)
    stdev_rate = statistics.stdev(normal_rates)

    z = zscore(typical_value, mean_rate, stdev_rate)
    assert abs(z) < 3.0, f"Expected normal value not to be flagged, got z={z}"


def test_zscore_handles_zero_stdev():
    z = zscore(100, 100, 0)
    assert z == 0.0