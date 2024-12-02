#!/bin/bash

# Define the analysis folder
analysis_folder="analysis"
# Define the output CSV file
output_csv="analysis_summary.csv"

# Write the CSV header
echo "Subfolder,Alerts,Filestore files,Protocol transactions" > "$output_csv"

# Loop through each subfolder in the analysis folder
for subfolder in "$analysis_folder"/*; do
    # Define the log file path
    log_file="$subfolder/suricata.log"
    
    # Initialize variables
    alert_count=0
    file_count=0
    protocol_transactions=0
    
    # Check if the log file exists
    if [[ -f "$log_file" ]]; then
        # Extract the number of alerts from the specified line format
        alert_count=$(grep "counters: Alerts:" "$log_file" | awk -F'Alerts: ' '{print $2}')
    fi

    # Check if the filestore subfolder exists
    if [[ -d "$subfolder/filestore" ]]; then
        # Count the number of files in the filestore subfolder
        file_count=$(find "$subfolder/filestore" -type f | wc -l)
    fi

    # Check if the eve.json file exists
    if [[ -f "$subfolder/eve.json" ]]; then
        # Parse the number of protocol transactions
        protocol_transactions=$(cat "$subfolder/eve.json" | jq -r '. | select(.event_type == "smb" or .event_type == "http" or .event_type == "ftp" or .event_type == "tcp") | .event_type' | sort | uniq -c | awk '{sum += $1} END {print sum}')
    fi
    
    # Print the subfolder name, the number of alerts, the number of files in filestore, and the number of protocol transactions
    echo "Subfolder: $(basename "$subfolder"), Alerts: $alert_count, Filestore files: $file_count, Protocol transactions: $protocol_transactions"
    
    # Append the data to the CSV file
    echo "$(basename "$subfolder"),$alert_count,$file_count,$protocol_transactions" >> "$output_csv"
done