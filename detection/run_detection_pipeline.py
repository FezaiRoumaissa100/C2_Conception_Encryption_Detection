import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

class BeaconingDetectionPipeline:
    """Complete C2 beaconing detection analysis"""
    
    def __init__(self, logs_dir="logs/tshark_logs"):
        self.logs_dir = Path(logs_dir)
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "status": "pending",
            "analyses": {},
            "detections": []
        }
        
        # C2 Configuration (adjust as needed)
        self.C2_SERVER = '192.168.1.163'
        self.C2_PORT = 5000
        self.VICTIM_IP = '192.168.1.160'
        
    def load_data(self):
        """Load network traffic logs"""
        print("\n" + "=" * 80)
        print("STEP 1: LOADING DATA")
        print("=" * 80)
        
        try:
            self.conn_df = pd.read_csv(self.logs_dir / 'conn.log')
            print(f"✓ conn.log loaded: {len(self.conn_df)} entries")
            
            self.beacon_df = np.loadtxt(
                self.logs_dir / 'beacon_timing.log', 
                delimiter=',',
                skiprows=0
            )
            print(f"✓ beacon_timing.log loaded: {len(self.beacon_df)} entries")
            
            # Try to load SSL logs
            try:
                self.ssl_df = pd.read_csv(self.logs_dir / 'ssl.log')
                print(f"✓ ssl.log loaded: {len(self.ssl_df)} entries")
            except:
                print("⚠ ssl.log empty or not found (expected for non-TLS C2)")
                self.ssl_df = None
                
            return True
        except Exception as e:
            print(f"✗ Error loading data: {e}")
            return False
    
    def analyze_beaconing_pattern(self):
        """Analyze beaconing pattern in network connections"""
        print("\n" + "=" * 80)
        print("STEP 2: BEACONING PATTERN ANALYSIS")
        print("=" * 80)
        
        # Filter C2 connections
        c2_conn = self.conn_df[
            (self.conn_df['ip.src'] == self.VICTIM_IP) & 
            (self.conn_df['ip.dst'] == self.C2_SERVER) & 
            (self.conn_df['tcp.dstport'] == self.C2_PORT)
        ].copy()
        
        if len(c2_conn) == 0:
            print(f"✗ No connections found: {self.VICTIM_IP} → {self.C2_SERVER}:{self.C2_PORT}")
            self.results["analyses"]["beaconing"] = {
                "status": "no_data",
                "connections": 0
            }
            return False
        
        # Sort by timestamp
        c2_conn = c2_conn.sort_values('frame.time_epoch').reset_index(drop=True)
        
        timestamps = c2_conn['frame.time_epoch'].values
        intervals = np.diff(timestamps)
        
        print(f"✓ Detected {len(c2_conn)} C2 connections")
        print(f"✓ Calculated {len(intervals)} intervals")
        
        if len(intervals) < 2:
            print("✗ Insufficient intervals for analysis")
            return False
        
        # Calculate statistics
        mean_interval = np.mean(intervals)
        median_interval = np.median(intervals)
        std_interval = np.std(intervals)
        min_interval = np.min(intervals)
        max_interval = np.max(intervals)
        cv = (std_interval / mean_interval) * 100
        
        # Beaconing score: 1.0 = perfect beaconing, 0.0 = random
        beacon_score = max(0, min(1, 1 - (cv / 100)))
        
        duration = timestamps[-1] - timestamps[0]
        freq_per_min = len(timestamps) / (duration / 60)
        freq_per_hour = len(timestamps) / (duration / 3600)
        
        # Confidence assessment
        if beacon_score > 0.7:
            confidence = "HIGH"
        elif beacon_score > 0.5:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        analysis = {
            "status": "success",
            "victim_ip": self.VICTIM_IP,
            "c2_server": f"{self.C2_SERVER}:{self.C2_PORT}",
            "total_connections": len(c2_conn),
            "statistics": {
                "mean_interval_sec": float(mean_interval),
                "median_interval_sec": float(median_interval),
                "std_deviation": float(std_interval),
                "min_interval": float(min_interval),
                "max_interval": float(max_interval),
                "coefficient_variation_percent": float(cv)
            },
            "beacon_score": float(beacon_score),
            "confidence": confidence,
            "jitter_percent": float(cv),
            "frequency": {
                "per_minute": float(freq_per_min),
                "per_hour": float(freq_per_hour)
            },
            "capture_duration_seconds": float(duration),
            "sample_intervals": [float(i) for i in intervals[:20]]
        }
        
        self.results["analyses"]["beaconing"] = analysis
        
        # Print results
        print("\n" + "-" * 80)
        print("BEACONING STATISTICS")
        print("-" * 80)
        print(f"Mean interval:           {mean_interval:.2f} seconds")
        print(f"Median interval:         {median_interval:.2f} seconds")
        print(f"Std deviation:           {std_interval:.2f} seconds")
        print(f"Coefficient of Variation: {cv:.2f}%")
        print(f"Beacon Score:            {beacon_score:.3f} [{confidence}]")
        print(f"Detected Jitter:         ±{cv:.1f}%")
        print(f"Frequency:               {freq_per_min:.2f} per minute / {freq_per_hour:.2f} per hour")
        print(f"Capture Duration:        {duration/60:.2f} minutes ({duration/3600:.2f} hours)")
        
        if beacon_score > 0.7:
            print("\n⚠ ALERT: HIGH CONFIDENCE C2 BEACONING PATTERN DETECTED")
            self.results["detections"].append({
                "type": "beaconing",
                "ip": self.VICTIM_IP,
                "score": beacon_score,
                "interval": mean_interval
            })
        
        return True
    
    def analyze_beacon_timing(self):
        """Analyze beacon timing from beacon_timing.log"""
        print("\n" + "=" * 80)
        print("STEP 3: BEACON TIMING ANALYSIS")
        print("=" * 80)
        
        try:
            timestamps = self.beacon_df[:, 0]
            packet_sizes = self.beacon_df[:, 1]
            
            intervals = np.diff(timestamps)
            
            if len(intervals) < 2:
                print("✗ Insufficient beacon timing data")
                return False
            
            mean_interval = np.mean(intervals)
            median_interval = np.median(intervals)
            std_interval = np.std(intervals)
            cv = (std_interval / mean_interval) * 100 if mean_interval > 0 else 0
            
            beacon_score = max(0, min(1, 1 - (cv / 100)))
            
            if beacon_score > 0.7:
                confidence = "HIGH"
            elif beacon_score > 0.5:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            
            duration = timestamps[-1] - timestamps[0]
            
            analysis = {
                "status": "success",
                "total_packets": len(timestamps),
                "packet_size": float(packet_sizes[0]),
                "packet_size_consistency": float(np.std(packet_sizes)),
                "statistics": {
                    "mean_interval_sec": float(mean_interval),
                    "median_interval_sec": float(median_interval),
                    "std_deviation": float(std_interval),
                    "coefficient_variation_percent": float(cv)
                },
                "beacon_score": float(beacon_score),
                "confidence": confidence,
                "jitter_percent": float(cv),
                "capture_duration_seconds": float(duration)
            }
            
            self.results["analyses"]["beacon_timing"] = analysis
            
            # Print results
            print("-" * 80)
            print("BEACON TIMING STATISTICS")
            print("-" * 80)
            print(f"Total beacon packets:    {len(timestamps)}")
            print(f"Packet size:             {int(packet_sizes[0])} bytes")
            print(f"Size consistency (σ):    {np.std(packet_sizes):.2f}")
            print(f"Mean interval:           {mean_interval:.2f} seconds")
            print(f"Median interval:         {median_interval:.2f} seconds")
            print(f"Std deviation:           {std_interval:.2f} seconds")
            print(f"Coefficient of Variation: {cv:.2f}%")
            print(f"Beacon Score:            {beacon_score:.3f} [{confidence}]")
            print(f"Detected Jitter:         ±{cv:.1f}%")
            print(f"Capture Duration:        {duration/60:.2f} minutes")
            
            if beacon_score > 0.7:
                print("\n⚠ ALERT: HIGH CONFIDENCE BEACON TIMING PATTERN DETECTED")
                self.results["detections"].append({
                    "type": "beacon_timing",
                    "packet_size": int(packet_sizes[0]),
                    "score": beacon_score,
                    "interval": mean_interval
                })
            
            return True
            
        except Exception as e:
            print(f"✗ Error analyzing beacon timing: {e}")
            return False
    
    def verify_ssl_certificates(self):
        """Verify SSL certificates against blacklist"""
        print("\n" + "=" * 80)
        print("STEP 4: SSL/TLS CERTIFICATE VERIFICATION")
        print("=" * 80)
        
        if self.ssl_df is None or len(self.ssl_df) == 0:
            print("ℹ No SSL/TLS certificates found in capture")
            print("  Possible reasons:")
            print("  1. C2 uses plain TCP without TLS")
            print("  2. Custom encryption (ChaCha20-Poly1305)")
            print("  3. Encrypted payload detected")
            
            analysis = {
                "status": "no_tls_found",
                "message": "No TLS handshakes in capture",
                "recommendation": "Verify C2 configuration for encryption method"
            }
            self.results["analyses"]["ssl_verification"] = analysis
            return True
        
        try:
            print(f"✓ Found {len(self.ssl_df)} SSL/TLS records")
            print("\nTo verify certificates against abuse.ch:")
            print("1. Extract certificate fingerprints (SHA1/SHA256)")
            print("2. Visit: https://sslbl.abuse.ch/")
            print("3. Search for certificate hash")
            print("4. Document findings")
            
            analysis = {
                "status": "requires_manual_verification",
                "records_found": len(self.ssl_df),
                "manual_steps": [
                    "Extract certificate fingerprints",
                    "Query abuse.ch database",
                    "Document blacklist status"
                ]
            }
            self.results["analyses"]["ssl_verification"] = analysis
            return True
            
        except Exception as e:
            print(f"✗ Error verifying SSL: {e}")
            return False
    
    def generate_report(self):
        """Generate comprehensive detection report"""
        print("\n" + "=" * 80)
        print("STEP 5: GENERATING REPORT")
        print("=" * 80)
        
        # Save JSON results
        json_file = Path("reports/detection_results.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        print(f"✓ JSON results saved: {json_file}")
        
        # Generate text report
        report_file = Path("reports/DETECTION_FINAL_REPORT.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("C2 CHANNEL DETECTION ANALYSIS REPORT\n")
            f.write("Blue Team - Detection Pipeline\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Beaconing Analysis
            if "beaconing" in self.results["analyses"]:
                ba = self.results["analyses"]["beaconing"]
                if ba["status"] == "success":
                    f.write("=" * 80 + "\n")
                    f.write("1. BEACONING PATTERN ANALYSIS\n")
                    f.write("=" * 80 + "\n\n")
                    
                    f.write(f"Victim IP:              {ba['victim_ip']}\n")
                    f.write(f"C2 Server:              {ba['c2_server']}\n")
                    f.write(f"Total Connections:      {ba['total_connections']}\n\n")
                    
                    f.write("Statistical Analysis:\n")
                    f.write(f"  Mean Interval:        {ba['statistics']['mean_interval_sec']:.2f} seconds\n")
                    f.write(f"  Median Interval:      {ba['statistics']['median_interval_sec']:.2f} seconds\n")
                    f.write(f"  Std Deviation:        {ba['statistics']['std_deviation']:.2f} seconds\n")
                    f.write(f"  Min Interval:         {ba['statistics']['min_interval']:.2f} seconds\n")
                    f.write(f"  Max Interval:         {ba['statistics']['max_interval']:.2f} seconds\n")
                    f.write(f"  Coefficient of Var:   {ba['statistics']['coefficient_variation_percent']:.2f}%\n\n")
                    
                    f.write(f"Beacon Score:           {ba['beacon_score']:.3f}\n")
                    f.write(f"Confidence:             {ba['confidence']}\n")
                    f.write(f"Detected Jitter:        ±{ba['jitter_percent']:.1f}%\n")
                    f.write(f"Frequency:              {ba['frequency']['per_minute']:.2f} /min, {ba['frequency']['per_hour']:.2f} /hour\n")
                    f.write(f"Capture Duration:       {ba['capture_duration_seconds']/60:.2f} minutes\n\n")
                    
                    if ba["beacon_score"] > 0.7:
                        f.write("DETECTION VERDICT: ⚠ HIGH CONFIDENCE C2 BEACONING DETECTED\n\n")
                    elif ba["beacon_score"] > 0.5:
                        f.write("DETECTION VERDICT: ⚠ MEDIUM CONFIDENCE POSSIBLE C2 ACTIVITY\n\n")
                    else:
                        f.write("DETECTION VERDICT: ℹ LOW CONFIDENCE - PATTERN UNCLEAR\n\n")
            
            # Beacon Timing Analysis
            if "beacon_timing" in self.results["analyses"]:
                bta = self.results["analyses"]["beacon_timing"]
                if bta["status"] == "success":
                    f.write("=" * 80 + "\n")
                    f.write("2. BEACON TIMING ANALYSIS\n")
                    f.write("=" * 80 + "\n\n")
                    
                    f.write(f"Total Beacon Packets:   {bta['total_packets']}\n")
                    f.write(f"Packet Size:            {bta['packet_size']} bytes\n")
                    f.write(f"Size Consistency (σ):   {bta['packet_size_consistency']:.2f}\n\n")
                    
                    f.write("Statistical Analysis:\n")
                    f.write(f"  Mean Interval:        {bta['statistics']['mean_interval_sec']:.2f} seconds\n")
                    f.write(f"  Median Interval:      {bta['statistics']['median_interval_sec']:.2f} seconds\n")
                    f.write(f"  Std Deviation:        {bta['statistics']['std_deviation']:.2f} seconds\n")
                    f.write(f"  Coefficient of Var:   {bta['statistics']['coefficient_variation_percent']:.2f}%\n\n")
                    
                    f.write(f"Beacon Score:           {bta['beacon_score']:.3f}\n")
                    f.write(f"Confidence:             {bta['confidence']}\n")
                    f.write(f"Detected Jitter:        ±{bta['jitter_percent']:.1f}%\n")
                    f.write(f"Capture Duration:       {bta['capture_duration_seconds']/60:.2f} minutes\n\n")
                    
                    if bta["beacon_score"] > 0.7:
                        f.write("DETECTION VERDICT: ⚠ HIGH CONFIDENCE BEACON PATTERN DETECTED\n\n")
            
            # SSL Verification
            if "ssl_verification" in self.results["analyses"]:
                sslv = self.results["analyses"]["ssl_verification"]
                f.write("=" * 80 + "\n")
                f.write("3. SSL/TLS CERTIFICATE VERIFICATION\n")
                f.write("=" * 80 + "\n\n")
                
                if sslv["status"] == "no_tls_found":
                    f.write("Status: NO TLS CERTIFICATES FOUND\n")
                    f.write("Possible reasons:\n")
                    f.write("  • C2 uses plain TCP without encryption\n")
                    f.write("  • Custom encryption protocol used\n")
                    f.write("  • Payload encrypted at application level\n\n")
                elif sslv["status"] == "requires_manual_verification":
                    f.write(f"Status: FOUND {sslv['records_found']} SSL/TLS RECORDS\n")
                    f.write("Manual verification required:\n")
                    for step in sslv["manual_steps"]:
                        f.write(f"  • {step}\n")
                    f.write("\nResources: https://sslbl.abuse.ch/\n\n")
            
            # Summary
            f.write("=" * 80 + "\n")
            f.write("SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            if len(self.results["detections"]) > 0:
                f.write(f"DETECTIONS FOUND: {len(self.results['detections'])}\n\n")
                for i, det in enumerate(self.results["detections"], 1):
                    f.write(f"Detection {i}:\n")
                    f.write(f"  Type: {det['type']}\n")
                    if 'ip' in det:
                        f.write(f"  IP: {det['ip']}\n")
                    if 'interval' in det:
                        f.write(f"  Interval: {det['interval']:.2f} seconds\n")
                    f.write(f"  Score: {det['score']:.3f}\n\n")
            else:
                f.write("No high-confidence C2 beaconing detected.\n\n")
            
            f.write("=" * 80 + "\n")
        
        print(f"✓ Report saved: {report_file}")
    
    def run(self):
        """Execute complete detection pipeline"""
        print("\n" + "█" * 80)
        print("█ C2 BEACONING DETECTION PIPELINE")
        print("█" * 80)
        
        if not self.load_data():
            print("\n✗ Pipeline failed: Could not load data")
            self.results["status"] = "failed"
            return False
        
        self.analyze_beaconing_pattern()
        self.analyze_beacon_timing()
        self.verify_ssl_certificates()
        self.generate_report()
        
        print("\n" + "=" * 80)
        print("✓ DETECTION PIPELINE COMPLETE")
        print("=" * 80)
        print("\nResults:")
        print(f"  • JSON Report: detection_results.json")
        print(f"  • Text Report: DETECTION_FINAL_REPORT.txt")
        
        if len(self.results["detections"]) > 0:
            print(f"\n⚠ DETECTIONS: {len(self.results['detections'])} high-confidence beacon(s) found")
        else:
            print("\nℹ No high-confidence detections found")
        
        self.results["status"] = "completed"
        return True


if __name__ == "__main__":
    pipeline = BeaconingDetectionPipeline()
    pipeline.run()
