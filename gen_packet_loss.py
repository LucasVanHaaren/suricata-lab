import os
import random
import sys
from scapy.all import rdpcap, wrpcap

def manipulate_pcap(file_path, output_dir, percentages, iterations):
    packets = rdpcap(file_path)
    total_packets = len(packets)
    print(f"Total packets: {total_packets}")
    base_name = os.path.basename(file_path).split('.')[0]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for percent in percentages:
        for iteration in range(1, iterations + 1):
            num_packets_to_remove = int(total_packets * (percent / 100))
            packets_to_remove = random.sample(range(total_packets), num_packets_to_remove)
            new_packets = [pkt for i, pkt in enumerate(packets) if i not in packets_to_remove]
            output_file = os.path.join(output_dir, f"{base_name}_{percent}_{iteration}.pcap")
            wrpcap(output_file, new_packets)
            print(f"Saved {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python packet_lost.py <input_pcap> <output_directory>")
        sys.exit(1)

    input_pcap = sys.argv[1]
    output_directory = sys.argv[2]
    loss_percentages = [0.5, 1, 1.5, 2, 5, 10, 25, 50]
    num_iterations = 3
    print("Starting")
    manipulate_pcap(input_pcap, output_directory, loss_percentages, num_iterations)
    print("Done!")
