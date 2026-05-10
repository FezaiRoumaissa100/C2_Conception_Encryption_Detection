#!/usr/bin/env python3
"""
C2 Detection Analysis Tool - Member 6
Analyzes network logs to detect encrypted C2 channel without decryption
"""

import csv
import json
import hashlib
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
import statistics

class C2Analyzer:
    def __init__(self, logs_dir):
        self.logs_dir = Path(logs_dir)
        self.results = {
            'metadata': {},
            'beacon_analysis': {},
            'connection_patterns': {},
            'dns_analysis': {},
            'tls_fingerprinting': {},
            'packet_size_analysis': {},
            'final_detection': {}
        }
        
    def parse_conn_log(self):
        """Parse connection log and extract connection patterns"""
        conn_file = self.logs_dir / 'conn.log'
        connections = []
        
        try:
            with open(conn_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    connections.append({
                        'timestamp': float(row['frame.time_epoch']),
                        'src_ip': row['ip.src'],
                        'dst_ip': row['ip.dst'],
                        'src_port': int(row['tcp.srcport']),
                        'dst_port': int(row['tcp.dstport']),
                        'packet_size': int(row['frame.len']),
                        'tcp_flags': row['tcp.flags']
                    })
        except FileNotFoundError:
            print(f"Warning: {conn_file} not found")
            
        return connections
    
    def parse_beacon_timing(self):
        """Parse beacon timing log"""
        beacon_file = self.logs_dir / 'beacon_timing.log'
        timings = []
        
        try:
            with open(beacon_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    timings.append({
                        'timestamp': float(row['frame.time_epoch']),
                        'interval': int(row.get('frame.time_epoch', 0)) if 'frame.time_epoch' in row else None
                    })
        except FileNotFoundError:
            print(f"Warning: {beacon_file} not found")
        except Exception as e:
            # If beacon_timing has different format, parse raw lines
            try:
                with open(beacon_file, 'r') as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.strip().split(',')
                        if len(parts) >= 2:
                            timings.append({
                                'timestamp': float(parts[0]),
                                'interval': int(parts[1]) if parts[1].isdigit() else None
                            })
            except:
                pass
        
        return timings
    
    def parse_ssl_log(self):
        """Parse SSL/TLS handshake log"""
        ssl_file = self.logs_dir / 'ssl.log'
        ssl_data = []
        
        try:
            with open(ssl_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ssl_data.append(row)
        except FileNotFoundError:
            print(f"Warning: {ssl_file} not found or has no data")
            
        return ssl_data
    
    def parse_dns_log(self):
        """Parse DNS log"""
        dns_file = self.logs_dir / 'dns.log'
        dns_data = []
        
        try:
            with open(dns_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    dns_data.append(row)
        except FileNotFoundError:
            print(f"Warning: {dns_file} not found or has no data")
            
        return dns_data
    
    def analyze_beacon_patterns(self, connections, timings):
        """Analyze beacon timing patterns"""
        if timings:
            intervals = [t['interval'] for t in timings if t['interval']]
            if intervals:
                self.results['beacon_analysis'] = {
                    'total_beacons': len(intervals),
                    'mean_interval': statistics.mean(intervals),
                    'median_interval': statistics.median(intervals),
                    'stdev_interval': statistics.stdev(intervals) if len(intervals) > 1 else 0,
                    'min_interval': min(intervals),
                    'max_interval': max(intervals),
                    'interval_distribution': dict(Counter(intervals))
                }
        
        # Analyze from connection log
        if connections:
            # Group by destination to identify command channel
            dst_connections = defaultdict(list)
            for conn in connections:
                key = f"{conn['dst_ip']}:{conn['dst_port']}"
                dst_connections[key].append(conn)
            
            # Find potential C2 server (most consistent destination)
            c2_candidates = {}
            for dst, conns in dst_connections.items():
                if len(conns) > 10:  # Filter out low-frequency connections
                    timestamps = sorted([c['timestamp'] for c in conns])
                    intervals = []
                    for i in range(1, len(timestamps)):
                        intervals.append(timestamps[i] - timestamps[i-1])
                    
                    if intervals:
                        mean_interval = statistics.mean(intervals)
                        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
                        
                        # Check if interval is between 30-120 seconds (typical beacon range)
                        if 30 <= mean_interval <= 120:
                            c2_candidates[dst] = {
                                'connection_count': len(conns),
                                'mean_interval': mean_interval,
                                'stdev_interval': stdev_interval,
                                'cv': (stdev_interval / mean_interval) if mean_interval > 0 else 0,  # Coefficient of variation
                                'jitter_percentage': (stdev_interval / mean_interval * 100) if mean_interval > 0 else 0
                            }
            
            self.results['beacon_analysis']['c2_candidates'] = c2_candidates
    
    def analyze_connection_patterns(self, connections):
        """Analyze packet sizes, timing, and connection characteristics"""
        if not connections:
            return
        
        # Packet size analysis
        packet_sizes = [c['packet_size'] for c in connections]
        self.results['packet_size_analysis'] = {
            'packet_count': len(packet_sizes),
            'mean_size': statistics.mean(packet_sizes),
            'median_size': statistics.median(packet_sizes),
            'stdev_size': statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else 0,
            'min_size': min(packet_sizes),
            'max_size': max(packet_sizes),
            'size_distribution': self._get_distribution(packet_sizes)
        }
        
        # TCP flags analysis (suspicious patterns)
        tcp_flags = Counter([c['tcp_flags'] for c in connections])
        
        # Connection patterns from specific source to C2
        src_to_dst = defaultdict(list)
        for conn in connections:
            key = f"{conn['src_ip']}->{conn['dst_ip']}:{conn['dst_port']}"
            src_to_dst[key].append(conn)
        
        suspicious_flows = {}
        for flow, conns in src_to_dst.items():
            sizes = [c['packet_size'] for c in conns]
            if len(conns) > 5:
                suspicious_flows[flow] = {
                    'packet_count': len(conns),
                    'mean_packet_size': statistics.mean(sizes),
                    'variance': statistics.variance(sizes) if len(sizes) > 1 else 0
                }
        
        self.results['connection_patterns'] = {
            'tcp_flags_distribution': dict(tcp_flags),
            'src_dst_flows': suspicious_flows,
            'unique_destinations': len(set(f"{c['dst_ip']}:{c['dst_port']}" for c in connections)),
            'unique_sources': len(set(c['src_ip'] for c in connections))
        }
    
    def _get_distribution(self, values, buckets=5):
        """Create distribution histogram"""
        if not values:
            return {}
        min_val = min(values)
        max_val = max(values)
        bucket_size = (max_val - min_val) / buckets if max_val > min_val else 1
        
        distribution = defaultdict(int)
        for val in values:
            bucket = int((val - min_val) // bucket_size) if bucket_size > 0 else 0
            distribution[f"bucket_{bucket}"] += 1
        
        return dict(distribution)
    
    def analyze_tls_fingerprinting(self, ssl_data):
        """Analyze TLS fingerprints from SSL/TLS handshake data"""
        if not ssl_data:
            self.results['tls_fingerprinting'] = {
                'status': 'No TLS data available in logs',
                'recommendation': 'Extract JA3 fingerprints from pcap using tshark or ja3 tool'
            }
            return
        
        # If SSL data exists, analyze it
        versions = Counter()
        ciphersuites = Counter()
        
        for entry in ssl_data:
            if 'tls.handshake.version' in entry and entry['tls.handshake.version']:
                versions[entry['tls.handshake.version']] += 1
            if 'tls.handshake.ciphersuite' in entry and entry['tls.handshake.ciphersuite']:
                ciphersuites[entry['tls.handshake.ciphersuite']] += 1
        
        self.results['tls_fingerprinting'] = {
            'tls_versions': dict(versions),
            'ciphersuites': dict(ciphersuites)
        }
    
    def generate_ja3_recommendation(self):
        """Generate commands to extract JA3 fingerprints"""
        return {
            'method_1_tshark': 'tshark -r c2_capture.pcap -Y tls.handshake -T fields -e tls.handshake.ja3',
            'method_2_ja3tool': 'ja3 c2_capture.pcap',
            'analysis_db': 'https://ja3er.com (database of known JA3 fingerprints)',
            'note': 'JA3 fingerprint uniquely identifies TLS client behavior without decryption'
        }
    
    def generate_detection_score(self):
        """Calculate overall C2 detection confidence"""
        score = 0
        indicators = []
        
        # Beacon pattern score
        if self.results['beacon_analysis']:
            beacon_data = self.results['beacon_analysis']
            if 'c2_candidates' in beacon_data and beacon_data['c2_candidates']:
                score += 40
                candidates = beacon_data['c2_candidates']
                for dst, data in candidates.items():
                    if 20 <= data['jitter_percentage'] <= 50:  # Typical C2 jitter range
                        indicators.append(f"✓ BEACON PATTERN DETECTED: {dst} with {data['jitter_percentage']:.1f}% jitter")
                        score += 10
        
        # Packet size consistency
        if self.results['packet_size_analysis']:
            pkt_analysis = self.results['packet_size_analysis']
            if pkt_analysis.get('stdev_size', 0) < pkt_analysis.get('mean_size', 1) * 0.5:
                score += 15
                indicators.append(f"✓ CONSISTENT PACKET SIZES: Low variance suggests automated communication")
        
        # Connection pattern score
        if self.results['connection_patterns']:
            conn_analysis = self.results['connection_patterns']
            if conn_analysis.get('unique_destinations', 0) == 1:
                score += 15
                indicators.append("✓ SINGLE C2 SERVER: All traffic to one destination")
            
            if 'src_dst_flows' in conn_analysis and len(conn_analysis['src_dst_flows']) > 0:
                score += 10
                indicators.append(f"✓ DEDICATED FLOW: {len(conn_analysis['src_dst_flows'])} suspicious data flows identified")
        
        self.results['final_detection'] = {
            'confidence_score': min(score, 100),
            'indicators_found': indicators,
            'threat_level': self._assess_threat_level(score)
        }
    
    def _assess_threat_level(self, score):
        if score >= 80:
            return "CRITICAL - C2 Channel Detected"
        elif score >= 60:
            return "HIGH - Strong C2 indicators"
        elif score >= 40:
            return "MEDIUM - Suspicious C2-like behavior"
        elif score >= 20:
            return "LOW - Minor anomalies detected"
        else:
            return "MINIMAL - Insufficient evidence"
    
    def run_analysis(self):
        """Run complete analysis"""
        print("[*] Parsing log files...")
        connections = self.parse_conn_log()
        timings = self.parse_beacon_timing()
        ssl_data = self.parse_ssl_log()
        dns_data = self.parse_dns_log()
        
        print(f"    - Parsed {len(connections)} connections")
        print(f"    - Parsed {len(timings)} beacon timing entries")
        print(f"    - Parsed {len(ssl_data)} SSL records")
        print(f"    - Parsed {len(dns_data)} DNS records")
        
        print("[*] Analyzing beacon patterns...")
        self.analyze_beacon_patterns(connections, timings)
        
        print("[*] Analyzing connection patterns...")
        self.analyze_connection_patterns(connections)
        
        print("[*] Analyzing TLS fingerprints...")
        self.analyze_tls_fingerprinting(ssl_data)
        
        print("[*] Generating detection score...")
        self.generate_detection_score()
        
        self.results['metadata'] = {
            'analysis_timestamp': datetime.now().isoformat(),
            'log_directory': str(self.logs_dir),
            'total_packets_analyzed': len(connections)
        }
        
        return self.results
    
    def save_results(self, output_file):
        """Save analysis results to JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"[+] Results saved to {output_file}")

if __name__ == '__main__':
    logs_dir = Path(__file__).parent / 'logs' / 'tshark_logs'
    
    analyzer = C2Analyzer(logs_dir)
    results = analyzer.run_analysis()
    
    # Save results
    analyzer.save_results(logs_dir.parent / 'c2_analysis_results.json')
    
    # Print summary
    print("\n" + "="*80)
    print("C2 DETECTION ANALYSIS SUMMARY")
    print("="*80)
    
    if results['final_detection']:
        print(f"\n📊 DETECTION SCORE: {results['final_detection']['confidence_score']}/100")
        print(f"🎯 THREAT LEVEL: {results['final_detection']['threat_level']}")
        print("\n🔍 Key Indicators:")
        for indicator in results['final_detection']['indicators_found']:
            print(f"   {indicator}")
    
    print(f"\n📈 Beacon Analysis:")
    if 'c2_candidates' in results['beacon_analysis']:
        for dst, data in results['beacon_analysis']['c2_candidates'].items():
            print(f"   {dst}: {data['mean_interval']:.1f}s interval (±{data['jitter_percentage']:.1f}%)")
    
    print(f"\n📦 Packet Analysis:")
    pkt = results['packet_size_analysis']
    if pkt:
        print(f"   Mean: {pkt.get('mean_size', 0):.0f} bytes | Median: {pkt.get('median_size', 0):.0f} bytes | StdDev: {pkt.get('stdev_size', 0):.0f}")
    
    print("\n" + "="*80)
