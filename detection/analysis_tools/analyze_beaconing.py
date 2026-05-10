import pandas as pd
import numpy as np

def analyze_beaconing(conn_log_path, c2_server, c2_port, victim_ip):
    """Analyze beaconing patterns in network traffic"""
    
    print("=" * 80)
    print("BEACONING PATTERN ANALYSIS")
    print("=" * 80)
    
    df = pd.read_csv(conn_log_path)
    
    c2_connections = df[
        (df['ip.src'] == victim_ip) & 
        (df['ip.dst'] == c2_server) & 
        (df['tcp.dstport'] == c2_port)
    ].copy()
    
    c2_connections = c2_connections.sort_values('frame.time_epoch')
    
    print(f"\nVictim IP: {victim_ip}")
    print(f"C2 Server: {c2_server}:{c2_port}")
    print(f"Total C2 connections: {len(c2_connections)}")
    
    timestamps = c2_connections['frame.time_epoch'].values
    intervals = np.diff(timestamps)
    
    if len(intervals) == 0:
        print("\nERROR: No intervals to analyze")
        return None
    
    print("\n" + "=" * 80)
    print("BEACONING STATISTICS")
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
        print("CONFIDENCE: HIGH - C2 beaconing pattern detected")
    elif beacon_score > 0.5:
        print("CONFIDENCE: MEDIUM - Possible C2 beaconing activity")
    else:
        print("CONFIDENCE: LOW - Pattern not consistent with beaconing")
    
    print("\n" + "=" * 80)
    print("SAMPLE INTERVALS (first 20 connections)")
    print("=" * 80)
    for i, interval in enumerate(intervals[:20]):
        print(f"Interval {i+1}: {interval:.2f} seconds")
    
    return {
        "mean": mean_interval,
        "median": median_interval,
        "std": std_interval,
        "min": min_interval,
        "max": max_interval,
        "cv": cv,
        "score": beacon_score,
        "connections": len(c2_connections)
    }


if __name__ == "__main__":
    # Default configuration
    C2_SERVER = '192.168.1.163'
    C2_PORT = 5000
    VICTIM_IP = '192.168.1.160'
    CONN_LOG = 'logs/tshark_logs/conn.log'
    
    analyze_beaconing(CONN_LOG, C2_SERVER, C2_PORT, VICTIM_IP)
