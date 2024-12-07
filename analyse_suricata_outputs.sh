#!/bin/bash

# Define the analysis folder
analysis_folder="analysis"
# Define the output CSV file
output_csv="analysis_summary.csv"
# Define a temporary file for storing intermediate results
temp_file="temp_analysis.csv"

# Write the CSV header
echo "Subfolder,Alerts,Filestore files,Protocol transactions" > "$output_csv"

# Loop through each subfolder in the analysis folder
for subfolder in "$analysis_folder"/*/; do
    # Loop through each pcap analysis folder in the current subfolder
    for pcap_folder in "$subfolder"/*/; do
        # Define the log file path
        log_file="$pcap_folder/suricata.log"
        
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
        if [[ -d "$pcap_folder/filestore" ]]; then
            # Count the number of files in the filestore subfolder
            file_count=$(find "$pcap_folder/filestore" -type f | wc -l)
        fi

        # Check if the eve.json file exists
        if [[ -f "$pcap_folder/eve.json" ]]; then
            # Parse the number of protocol transactions
            protocol_transactions=$(cat "$pcap_folder/eve.json" | jq -r '. | select(.event_type == "smb" or .event_type == "http" or .event_type == "ftp" or .event_type == "tcp") | .event_type' | sort | uniq -c | awk '{sum += $1} END {print sum}')
        fi
        
        # Print the subfolder name, the number of alerts, the number of files in filestore, and the number of protocol transactions
        echo "Subfolder: $(basename "$subfolder")/$(basename "$pcap_folder"), Alerts: $alert_count, Filestore files: $file_count, Protocol transactions: $protocol_transactions"
        
        # Append the data to the temporary file
        echo "$(basename "$subfolder")/$(basename "$pcap_folder"),$alert_count,$file_count,$protocol_transactions" >> "$temp_file"
    done
done

# Function to compute the median
compute_median() {
    arr=($(printf '%s\n' "$@" | sort -n))
    len=${#arr[@]}
    if (( $len % 2 == 1 )); then
        echo "${arr[$((len/2))]}"
    else
        echo $(( (arr[len/2-1] + arr[len/2]) / 2 ))
    fi
}

# Compute the median for each base_capture_X group
for base in $(awk -F'/' '{print $1}' "$temp_file" | sort | uniq); do
    alerts=($(grep "^$base" "$temp_file" | awk -F',' '{print $2}'))
    files=($(grep "^$base" "$temp_file" | awk -F',' '{print $3}'))
    transactions=($(grep "^$base" "$temp_file" | awk -F',' '{print $4}'))
    
    median_alerts=$(compute_median "${alerts[@]}")
    median_files=$(compute_median "${files[@]}")
    median_transactions=$(compute_median "${transactions[@]}")
    
    echo "$base,$median_alerts,$median_files,$median_transactions" >> "$output_csv"
done

# Clean up the temporary file
rm "$temp_file"