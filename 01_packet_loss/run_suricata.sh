#!/bin/bash

# Define the source and destination directories
SOURCE_DIR="./samples/base_capture"
DEST_DIR="./analysis/"

# Create the destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Loop through each subfolder in the source directory
for subfolder in "$SOURCE_DIR"/*/; do
    # Get the relative path of the subfolder (without the source directory)
    rel_path="${subfolder#$SOURCE_DIR/}"
    
    # Loop through each pcap file in the current subfolder
    for pcap_file in "$subfolder"/*.pcap; do
        # Get the base name of the pcap file (without the directory and extension)
        base_name=$(basename "$pcap_file" .pcap)
        
        # Create a destination folder with the same structure as the source folder
        dest_folder="$DEST_DIR/$rel_path$base_name"
        mkdir -p "$dest_folder"
        
        # Run suricata on the pcap file and output to the destination folder
        suricata -r "$pcap_file" -l "$dest_folder" -k none -v --runmode=single
    done
done
