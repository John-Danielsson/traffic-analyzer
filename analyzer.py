import pyshark
import argparse
import logging
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# Ethical Disclaimer
# This tool is for EDUCATIONAL and AUTHORIZED USE ONLY. Unauthorized packet capturing is illegal.

logging.basicConfig(filename='traffic_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

parser = argparse.ArgumentParser(description="Ethical Web Traffic Analyzer (Wireshark-inspired)")
parser.add_argument("--interface", required=True, help="Network interface (e.g., eth0, Wi-Fi)")
parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds")
parser.add_argument("--filter", default="http", help="BPF filter (e.g., 'http' for web traffic)")
parser.add_argument("--output", default="traffic_report.csv", help="Output CSV file")
args = parser.parse_args()

def capture_traffic(interface, duration, filter_str):
    logging.info(f"Starting capture on {interface} for {duration}s with filter '{filter_str}'")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=filter_str)
    capture.sniff(timeout=duration)
    logging.info(f"Capture complete: {len(capture)} packets")
    return capture

def analyze_packets(packets):
    data = []
    for pkt in packets:
        if 'http' in pkt:
            try:
                timestamp = pkt.sniff_time
                src_ip = pkt.ip.src if 'ip' in pkt else 'N/A'
                dst_ip = pkt.ip.dst if 'ip' in pkt else 'N/A'
                method = pkt.http.request_method if hasattr(pkt.http, 'request_method') else 'N/A'
                url = pkt.http.request_full_uri if hasattr(pkt.http, 'request_full_uri') else 'N/A'
                status = pkt.http.response_code if hasattr(pkt.http, 'response_code') else 'N/A'
                data.append({
                    'Timestamp': timestamp,
                    'Source IP': src_ip,
                    'Dest IP': dst_ip,
                    'Method': method,
                    'URL': url,
                    'Status': status
                })
                logging.info(f"Analyzed: {method} {url} ({status})")
            except Exception as e:
                logging.error(f"Error analyzing packet: {e}")
    return pd.DataFrame(data)

def generate_report(df, output_file):
    df.to_csv(output_file, index=False)
    print(f"Report saved to {output_file}")

    # Simple visualization
    if not df.empty:
        df['Method'].value_counts().plot(kind='bar')
        plt.title('HTTP Methods Distribution')
        plt.savefig('methods_chart.png')
        print("Chart saved to methods_chart.png")


if __name__ == "__main__":
    packets = capture_traffic(args.interface, args.duration, args.filter)
    df = analyze_packets(packets)
    generate_report(df, args.output)