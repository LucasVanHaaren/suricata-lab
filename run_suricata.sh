#!/bin/bash

# Define the source and destination directories
SOURCE_DIR="./samples/base_capture_packet_loss"
DEST_DIR="./analysis/"

# Create the destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Loop through each pcap file in the source directory
for pcap_file in "$SOURCE_DIR"/*.pcap; do
    # Get the base name of the pcap file (without the directory and extension)
    base_name=$(basename "$pcap_file" .pcap)
    
    # Create a destination folder with the same name as the pcap file
    dest_folder="$DEST_DIR/$base_name"
    mkdir -p "$dest_folder"
    
    # Run suricata on the pcap file and output to the destination folder
    suricata -r "$pcap_file" -l "$dest_folder" -k none -v --runmode=single
done
