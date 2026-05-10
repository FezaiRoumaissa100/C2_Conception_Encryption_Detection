import numpy as np

def analyze_beacon_timing(beacon_log_path):
    """Analyze beacon timing patterns"""
    
    print("=" * 80)
    print("BEACON TIMING LOG ANALYSIS")
    print("=" * 80)
    
    data = np.loadtxt(beacon_log_path, delimiter=',')
    timestamps = data[:, 0]
    packet_sizes = data[:, 1]
    
    print(f"\nTotal beacon packets: {len(timestamps)}")
    print(f"Consistent packet size: {int(packet_sizes[0])} bytes")
    
    intervals = np.diff(timestamps)
    
    if len(intervals) < 1:
        print("\nERROR: Insufficient beacon timing data")
        return None
    
    print("\n" + "=" * 80)
    print("BEACONING INTERVAL STATISTICS")
    print("=" * 80)
    
    mean_interval = np.mean(intervals)
    median_interval = np.median(intervals)
    std_interval = np.std(intervals)
    min_interval = np.min(intervals)
    max_interval = np.max(intervals)
    cv = (std_interval / mean_interval) * 100 if mean_interval > 0 else 0
    
    print(f"Mean interval:       {mean_interval:.2f} seconds")
    print(f"Median interval:     {median_interval:.2f} seconds")
    print(f"Standard deviation:  {std_interval:.2f} seconds")
    print(f"Minimum interval:    {min_interval:.2f} seconds")
    print(f"Maximum interval:    {max_interval:.2f} seconds")
    print(f"Coefficient of Variation: {cv:.2f}%")
    
    beacon_score = max(0, 1 - (cv / 100))
    print(f"\nBeacon Score: {beacon_score:.3f}")
    
    if beacon_score > 0.7:
        print("CONFIDENCE: HIGH - Regular beacon pattern detected")
    elif beacon_score > 0.5:
        print("CONFIDENCE: MEDIUM - Possible beacon pattern")
    else:
        print("CONFIDENCE: LOW - Pattern not consistent with beaconing")
    
    print("\n" + "=" * 80)
    print("COMPARISON TO EXPECTED VALUES")
    print("=" * 80)
    print(f"Expected beacon interval: ~60 seconds")
    print(f"Actual mean interval: {mean_interval:.2f} seconds")
    print(f"Expected jitter: +/- 30%")
    print(f"Actual jitter: +/- {cv:.1f}%")
    
    return {
        "mean": mean_interval,
        "median": median_interval,
        "std": std_interval,
        "min": min_interval,
        "max": max_interval,
        "cv": cv,
        "score": beacon_score,
        "packets": len(timestamps),
        "packet_size": int(packet_sizes[0])
    }


if __name__ == "__main__":
    BEACON_LOG = 'logs/tshark_logs/beacon_timing.log'
    analyze_beacon_timing(BEACON_LOG)
