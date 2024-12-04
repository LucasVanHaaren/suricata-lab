import os
import random
import sys
from scapy.all import rdpcap, wrpcap

ITERATIONS = 3

def packet_loss(file_path, output_dir, percentages, iterations):
    packets = rdpcap(file_path)
    total_packets = len(packets)
    base_name = os.path.basename(file_path).split('.')[0]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for percent in percentages:
        for iteration in range(1, iterations + 1):
            num_packets_to_remove = int(total_packets * (percent / 100))
            packets_to_remove = random.sample(range(total_packets), num_packets_to_remove)
            new_packets = [pkt for i, pkt in enumerate(packets) if i not in packets_to_remove]
            output_file = os.path.join(output_dir, f"{base_name}/{percent}/{iteration}.pcap")
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            wrpcap(output_file, new_packets)
            print(f"Saved {percent}% packet loss iteration {iteration} in \t{output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python packet_lost.py <input_pcap> <output_directory>")
        sys.exit(1)

    input_pcap = sys.argv[1]
    output_directory = sys.argv[2]
    loss_percentages = [0.5, 1, 1.5, 2, 5, 10, 25, 50]
    print("Packet loss generation ...")
    packet_loss(input_pcap, output_directory, loss_percentages, ITERATIONS)
    print("Done!")
