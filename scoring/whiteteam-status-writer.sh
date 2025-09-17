#!/bin/bash

# CTF Status Writer Script - Reads results from scoring scripts and writes to remote /status.txt
# This script reads from the output files of curl-database.sh and ssh-backdoors.sh

# Configuration
SSH_TIMEOUT=10
STATUS_FILE="/status.txt"
LOG_FILE="/tmp/whiteteam-status-writer.log"
SCP_STATUS_FILE="/tmp/whiteteam-scp-status.txt"  # File to track SCP success/failure per IP
MAX_THREADS=50  # Maximum number of parallel SCP operations

# Score files from the other scripts
CURL_SCORE_FILE="/tmp/stage-1-scores.txt"
SSH_SCORE_FILE="/tmp/ssh-backdoor-scores.txt"

# Temporary copies of score files (stable snapshots)
CURL_SCORE_COPY="/tmp/stage-1-scores-copy.txt"
SSH_SCORE_COPY="/tmp/ssh-backdoor-scores-copy.txt"

# Function to copy score files to temporary locations for stable reading
copy_score_files() {
    echo "Creating stable copies of score files..."
    
    local copy_success=true
    
    # Copy CURL score file if it exists
    if [ -f "$CURL_SCORE_FILE" ]; then
        if cp "$CURL_SCORE_FILE" "$CURL_SCORE_COPY" 2>/dev/null; then
            echo "  ✓ Database scores copied: $(wc -l < "$CURL_SCORE_COPY") entries"
        else
            echo "  ✗ Failed to copy database scores"
            copy_success=false
        fi
    else
        echo "  ⚠ Database scores file not found, creating empty copy"
        touch "$CURL_SCORE_COPY"
    fi
    
    # Copy SSH score file if it exists
    if [ -f "$SSH_SCORE_FILE" ]; then
        if cp "$SSH_SCORE_FILE" "$SSH_SCORE_COPY" 2>/dev/null; then
            echo "  ✓ SSH scores copied: $(wc -l < "$SSH_SCORE_COPY") entries"
        else
            echo "  ✗ Failed to copy SSH scores"
            copy_success=false
        fi
    else
        echo "  ⚠ SSH scores file not found, creating empty copy"
        touch "$SSH_SCORE_COPY"
    fi
    
    if [ "$copy_success" = true ]; then
        echo "  Score file copies created successfully"
        return 0
    else
        echo "  Some files failed to copy"
        return 1
    fi
}

# Function to cleanup temporary score file copies
cleanup_score_copies() {
    echo "Cleaning up temporary score file copies..."
    rm -f "$CURL_SCORE_COPY" "$SSH_SCORE_COPY"
    echo "  Temporary files removed"
}

# Function to wait for score files to exist and be completed
wait_for_score_files() {
    echo "Waiting for score files to be available and completed..."
    echo "Checking for:"
    echo "  - $CURL_SCORE_FILE"
    echo "  - $SSH_SCORE_FILE"
    echo ""
    
    local file_stability_seconds=5  # Files must be stable (unchanged) for this many seconds
    local check_interval=2          # Check every 2 seconds
    local last_curl_mtime=""
    local last_ssh_mtime=""
    local stable_curl_count=0
    local stable_ssh_count=0
    local required_stable_checks=$((file_stability_seconds / check_interval))
    local curl_copied=false
    local ssh_copied=false
    
    while true; do
        local curl_exists=false
        local ssh_exists=false
        local curl_stable=false
        local ssh_stable=false
        
        # Check if CURL score file exists and get its modification time
        if [ -f "$CURL_SCORE_FILE" ]; then
            curl_exists=true
            local current_curl_mtime=$(stat -c %Y "$CURL_SCORE_FILE" 2>/dev/null)
            
            if [ "$current_curl_mtime" = "$last_curl_mtime" ]; then
                ((stable_curl_count++))
                if [ $stable_curl_count -ge $required_stable_checks ]; then
                    curl_stable=true
                fi
            else
                stable_curl_count=0
                last_curl_mtime="$current_curl_mtime"
                # If file changed, mark as not copied
                curl_copied=false
            fi
        else
            stable_curl_count=0
            last_curl_mtime=""
            curl_copied=false
        fi
        
        # Check if SSH score file exists and get its modification time
        if [ -f "$SSH_SCORE_FILE" ]; then
            ssh_exists=true
            local current_ssh_mtime=$(stat -c %Y "$SSH_SCORE_FILE" 2>/dev/null)
            
            if [ "$current_ssh_mtime" = "$last_ssh_mtime" ]; then
                ((stable_ssh_count++))
                if [ $stable_ssh_count -ge $required_stable_checks ]; then
                    ssh_stable=true
                fi
            else
                stable_ssh_count=0
                last_ssh_mtime="$current_ssh_mtime"
                # If file changed, mark as not copied
                ssh_copied=false
            fi
        else
            stable_ssh_count=0
            last_ssh_mtime=""
            ssh_copied=false
        fi
        
        # Copy files individually as they become ready
        if [ "$curl_stable" = true ] && [ "$curl_copied" = false ]; then
            echo ""
            echo "✓ Database score file is ready! Copying..."
            if cp "$CURL_SCORE_FILE" "$CURL_SCORE_COPY" 2>/dev/null; then
                echo "  Database scores copied: $(wc -l < "$CURL_SCORE_COPY") entries"
                curl_copied=true
            else
                echo "  ✗ Failed to copy database scores"
            fi
        fi
        
        if [ "$ssh_stable" = true ] && [ "$ssh_copied" = false ]; then
            echo ""
            echo "✓ SSH score file is ready! Copying..."
            if cp "$SSH_SCORE_FILE" "$SSH_SCORE_COPY" 2>/dev/null; then
                echo "  SSH scores copied: $(wc -l < "$SSH_SCORE_COPY") entries"
                ssh_copied=true
            else
                echo "  ✗ Failed to copy SSH scores"
            fi
        fi
        
        # Show current status
        local timestamp=$(date '+%H:%M:%S')
        local curl_status="MISSING"
        local ssh_status="MISSING"
        
        if [ "$curl_exists" = true ]; then
            if [ "$curl_copied" = true ]; then
                curl_status="READY (COPIED)"
            elif [ "$curl_stable" = true ]; then
                curl_status="READY"
            else
                curl_status="UPDATING (${stable_curl_count}/${required_stable_checks})"
            fi
        fi
        
        if [ "$ssh_exists" = true ]; then
            if [ "$ssh_copied" = true ]; then
                ssh_status="READY (COPIED)"
            elif [ "$ssh_stable" = true ]; then
                ssh_status="READY"
            else
                ssh_status="UPDATING (${stable_ssh_count}/${required_stable_checks})"
            fi
        fi
        
        echo "[$timestamp] Database scores: $curl_status | SSH scores: $ssh_status"
        
        # Check if both files are ready and copied
        if [ "$curl_copied" = true ] && [ "$ssh_copied" = true ]; then
            echo ""
            echo "✓ Both score files are available, stable, and copied!"
            echo "  Database scores: $(wc -l < "$CURL_SCORE_COPY") entries (from: $(stat -c %y "$CURL_SCORE_FILE"))"
            echo "  SSH scores: $(wc -l < "$SSH_SCORE_COPY") entries (from: $(stat -c %y "$SSH_SCORE_FILE"))"
            echo ""
            echo "Ready to process with stable score file copies"
            return 0
        fi
        
        # Wait before next check
        sleep $check_interval
    done
}

# Function to get IPs from OpenTofu
get_ips_from_tofu() {
    local tofu_dir="/home/debian/blueteam/opentofu"
    
    if [ ! -d "$tofu_dir" ]; then
        echo "Error: OpenTofu directory not found at $tofu_dir" >&2
        return 1
    fi
    
    cd "$tofu_dir" || return 1
    
    local tofu_output=$(tofu output -json 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Error: Failed to get tofu output" >&2
        return 1
    fi
    
    echo "$tofu_output" | jq -r '.debian_vm_ips.value[]' 2>/dev/null
}

# Function to parse curl database results for an IP
get_curl_status() {
    local ip="$1"
    
    if [ ! -f "$CURL_SCORE_COPY" ]; then
        echo "UNKNOWN:NO_DATA"
        return
    fi
    
    # Format: IP Health_Status Success_Rate Command_Injection_Vulnerable CPUINFO_Injection_Vulnerable
    # Example: 100.65.2.8 true 25/30 (83.33%) false false
    local curl_line=$(grep "^$ip " "$CURL_SCORE_COPY" 2>/dev/null)
    echo "$curl_line" > /tmp/test.txt
    if [ -z "$curl_line" ]; then
        echo "UNKNOWN:NO_DATA"
        return
    fi
    
    # Parse the line
    local health_status=$(echo "$curl_line" | awk '{print $2}')
    local success_rate=$(echo "$curl_line" | awk '{print $3}')
    local cmd_injection=$(echo "$curl_line" | awk '{print $4}')
    local cpuinfo_injection=$(echo "$curl_line" | awk '{print $5}')
    # Determine overall database status
    local db_status="UNHEALTHY"
    if [ "$health_status" = "true" ]; then
        db_status="HEALTHY"
    fi
    
    # Determine injection vulnerability status
    local injection_status="SECURE"
    if [ "$cmd_injection" = "true" ] || [ "$cpuinfo_injection" = "true" ]; then
        local backdoor1_status="SECURE"
        local backdoor2_status="SECURE"
        
        if [ "$cmd_injection" = "true" ]; then
            backdoor1_status="VULNERABLE"
        fi
        
        if [ "$cpuinfo_injection" = "true" ]; then
            backdoor2_status="VULNERABLE"
        fi
        
        injection_status="BACKDOOR 1 ${backdoor1_status} /// BACKDOOR 2 ${backdoor2_status}"
    fi
    
    echo "${db_status}:${success_rate}:${injection_status}"
}

# Function to parse SSH backdoor results for an IP
get_ssh_status() {
    local ip="$1"
    
    if [ ! -f "$SSH_SCORE_COPY" ]; then
        echo "UNKNOWN:NO_DATA"
        return
    fi
    
    # Format: IP Overall_Secure Root_Backdoor_Detected Blueteam_Backdoor_Detected
    # Example: 100.65.2.8 true false false
    local ssh_line=$(grep "^$ip " "$SSH_SCORE_COPY" 2>/dev/null)
    
    if [ -z "$ssh_line" ]; then
        echo "UNKNOWN:NO_DATA"
        return
    fi
    
    # Parse the line
    local overall_secure=$(echo "$ssh_line" | awk '{print $2}')
    local root_backdoor=$(echo "$ssh_line" | awk '{print $3}')
    local blueteam_backdoor=$(echo "$ssh_line" | awk '{print $4}')
    
    # Determine overall SSH status
    local ssh_status="SECURE"
    if [ "$overall_secure" = "false" ]; then
        ssh_status="COMPROMISED"
    fi
    
    # Determine specific backdoor details
    local backdoor_details="NONE"
    if [ "$root_backdoor" = "true" ] && [ "$blueteam_backdoor" = "true" ]; then
        backdoor_details="ROOT+BLUETEAM"
    elif [ "$root_backdoor" = "true" ]; then
        backdoor_details="ROOT_ONLY"
    elif [ "$blueteam_backdoor" = "true" ]; then
        backdoor_details="BLUETEAM_ONLY"
    fi
    
    echo "${ssh_status}:${backdoor_details}"
}

# Function to initialize SCP status file
init_scp_status_file() {
    echo "# SCP Status Report - $(date '+%Y-%m-%d %H:%M:%S')" > "$SCP_STATUS_FILE"
    echo "# Format: IP_ADDRESS STATUS [SUCCESS|FAILED] [DETAILS]" >> "$SCP_STATUS_FILE"
    echo "# Generated by CTF Whiteteam Status Writer" >> "$SCP_STATUS_FILE"
    echo "" >> "$SCP_STATUS_FILE"
    echo "SCP status file initialized: $SCP_STATUS_FILE"
}

# Function to update SCP status for an IP
update_scp_status() {
    local ip="$1"
    local status="$2"
    local details="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Append to SCP status file (thread-safe with >>)
    echo "$ip $status $timestamp $details" >> "$SCP_STATUS_FILE"
}

# Function to write status to remote host using whiteteam:whiteteam credentials
write_status_to_remote() {
    local ip="$1"
    
    echo "[$(date '+%H:%M:%S')] Processing status for $ip..." >> "$LOG_FILE"
    
    # Get status from both scoring scripts
    local curl_status=$(get_curl_status "$ip")
    local ssh_status=$(get_ssh_status "$ip")
    
    # Parse curl status
    local db_health=$(echo "$curl_status" | cut -d: -f1)
    local success_rate=$(echo "$curl_status" | cut -d: -f2)
    local injection_vuln=$(echo "$curl_status" | cut -d: -f3)
    
    # Parse SSH status
    local ssh_security=$(echo "$ssh_status" | cut -d: -f1)
    local backdoor_details=$(echo "$ssh_status" | cut -d: -f2)
    
    # Create status content
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local status_content="=== SYSTEM STATUS REPORT ===
Generated: $timestamp
Target IP: $ip

=== WEB DATABASE SERVICE STATUS ===
Health Status: $db_health
Success Rate: $success_rate
Port 80 Command Injection: $injection_vuln

=== SSH SECURITY STATUS ===
Overall Security: $ssh_security
Backdoor Detection: $backdoor_details
==============================="

    # Write status content to local temporary file
    local temp_file="/tmp/status_${ip//\./_}.txt"
    echo "$status_content" > "$temp_file"
    
    # Use scp to copy the file to the remote host
    if command -v sshpass >/dev/null 2>&1; then
        local scp_result=$(timeout $SSH_TIMEOUT sshpass -p "whiteteam" scp -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$temp_file" whiteteam@$ip:$STATUS_FILE 2>&1)
        local scp_exit_code=$?
        
        # Clean up local temp file
        rm -f "$temp_file"
        
        if [[ $scp_exit_code -eq 0 ]]; then
            # Verify the file was copied successfully
            local verify_result=$(timeout $SSH_TIMEOUT sshpass -p "whiteteam" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=yes -o PubkeyAuthentication=no whiteteam@$ip "ls -la $STATUS_FILE 2>/dev/null | head -1" 2>/dev/null)
            local verify_exit_code=$?
            
            if [[ $verify_exit_code -eq 0 ]] && [[ "$verify_result" =~ "$STATUS_FILE" ]]; then
                echo "[$(date '+%H:%M:%S')] ✓ $ip - Status successfully updated ($db_health, $ssh_security)" >> "$LOG_FILE"
                update_scp_status "$ip" "SUCCESS" "File_copied_and_verified"
                echo "SUCCESS: $ip - Status: DB=$db_health SSH=$ssh_security"
                return 0
            else
                echo "[$(date '+%H:%M:%S')] ✗ $ip - File copied but verification failed" >> "$LOG_FILE"
                update_scp_status "$ip" "FAILED" "File_copied_but_verification_failed"
                echo "WARNING: $ip - File copied but verification failed"
                return 1
            fi
        else
            echo "[$(date '+%H:%M:%S')] ✗ $ip - SCP failed (exit: $scp_exit_code): $scp_result" >> "$LOG_FILE"
            update_scp_status "$ip" "FAILED" "SCP_failed_exit_code_${scp_exit_code}"
            echo "FAILED: $ip - Could not copy status file (SCP failed)"
            return 1
        fi
    else
        echo "[$(date '+%H:%M:%S')] ✗ $ip - sshpass not available" >> "$LOG_FILE"
        update_scp_status "$ip" "FAILED" "sshpass_not_available"
        echo "FAILED: $ip - sshpass not available for password authentication"
        rm -f "$temp_file"
        return 1
    fi
}

# Function to write status to remote host using whiteteam:whiteteam credentials (threaded version)
write_status_to_remote_threaded() {
    local ip="$1"
    local thread_id="$2"
    
    echo "[$(date '+%H:%M:%S')] Thread $thread_id: Processing status for $ip..." >> "$LOG_FILE"
    
    # Get status from both scoring scripts
    local curl_status=$(get_curl_status "$ip")
    local ssh_status=$(get_ssh_status "$ip")
    
    # Parse curl status
    local db_health=$(echo "$curl_status" | cut -d: -f1)
    local success_rate=$(echo "$curl_status" | cut -d: -f2)
    local injection_vuln=$(echo "$curl_status" | cut -d: -f3)
    
    # Parse SSH status
    local ssh_security=$(echo "$ssh_status" | cut -d: -f1)
    local backdoor_details=$(echo "$ssh_status" | cut -d: -f2)
    
    # Create status content
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local status_content="=== SYSTEM STATUS REPORT ===
Generated: $timestamp
Target IP: $ip

=== WEB DATABASE SERVICE STATUS ===
Health Status: $db_health
Success Rate: $success_rate
Port 80 Command Injection: $injection_vuln

=== SSH SECURITY STATUS ===
Overall Security: $ssh_security
Backdoor Detection: $backdoor_details
"

    # Write status content to local temporary file with thread-safe naming
    local temp_file="/tmp/status_${ip//\./_}_${thread_id}.txt"
    echo "$status_content" > "$temp_file"
    
    # Use scp to copy the file to the remote host
    if command -v sshpass >/dev/null 2>&1; then
        local scp_result=$(timeout $SSH_TIMEOUT sshpass -p "whiteteam" scp -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$temp_file" whiteteam@"$ip":$STATUS_FILE 2>&1)
        local scp_exit_code=$?
        
        # Clean up local temp file
        rm -f "$temp_file"
        
        if [[ $scp_exit_code -eq 0 ]]; then
            # Write success to thread-specific result file
            echo "$ip:SUCCESS" >> "/tmp/results_${thread_id}.tmp"
            update_scp_status "$ip" "SUCCESS" "Thread_${thread_id}_SCP_successful"
            echo "[$(date '+%H:%M:%S')] Thread $thread_id: ✓ $ip - Status successfully updated ($db_health, $ssh_security)" >> "$LOG_FILE"
            return 0
        else
            echo "$ip:FAILED" >> "/tmp/results_${thread_id}.tmp"
            update_scp_status "$ip" "FAILED" "Thread_${thread_id}_SCP_failed_exit_code_${scp_exit_code}"
            echo "[$(date '+%H:%M:%S')] Thread $thread_id: ✗ $ip - SCP failed (exit: $scp_exit_code): $scp_result" >> "$LOG_FILE"
            return 1
        fi
    else
        echo "$ip:FAILED" >> "/tmp/results_${thread_id}.tmp"
        update_scp_status "$ip" "FAILED" "Thread_${thread_id}_sshpass_not_available"
        echo "[$(date '+%H:%M:%S')] Thread $thread_id: ✗ $ip - sshpass not available" >> "$LOG_FILE"
        rm -f "$temp_file"
        return 1
    fi
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for sshpass
    if ! command -v sshpass >/dev/null 2>&1; then
        missing_deps+=("sshpass")
    fi
    
    # Check for curl
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    # Check for jq
    if ! command -v jq >/dev/null 2>&1; then
        missing_deps+=("jq")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo "Error: Missing dependencies: ${missing_deps[*]}"
        echo "Please install them with: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
}

# Function to verify whiteteam credentials work on a single host
test_whiteteam_credentials() {
    local ip="$1"
    
    echo "Testing whiteteam:whiteteam credentials on $ip..."
    local test_result=$(timeout $SSH_TIMEOUT sshpass -p "whiteteam" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=yes -o PubkeyAuthentication=no whiteteam@$ip "whoami && echo 'WHITETEAM_ACCESS_CONFIRMED'" 2>/dev/null)
    local test_exit_code=$?
    
    if [[ $test_exit_code -eq 0 ]] && [[ "$test_result" =~ "whiteteam" ]] && [[ "$test_result" =~ "WHITETEAM_ACCESS_CONFIRMED" ]]; then
        echo "✓ whiteteam credentials work on $ip"
        return 0
    else
        echo "✗ whiteteam credentials failed on $ip (exit code: $test_exit_code)"
        return 1
    fi
}

# Main function
main() {
    echo "============================================="
    echo "CTF Whiteteam Status Writer (Score Reader)"
    echo "============================================="
    echo "Timestamp: $(date)"
    echo "Target status file: $STATUS_FILE"
    echo "Reading from:"
    echo "  - Database scores: $CURL_SCORE_FILE"
    echo "  - SSH scores: $SSH_SCORE_FILE"
    echo ""
    
    # Check dependencies
    echo "Checking dependencies..."
    check_dependencies
    echo "✓ All dependencies available"
    echo ""
    
    # Initialize log file and SCP status file
    echo "[$(date '+%H:%M:%S')] CTF Whiteteam Status Writer Started (Score Reader Mode)" > "$LOG_FILE"
    init_scp_status_file
    
    # Wait for score files to be ready
    wait_for_score_files
    
    # Get IP addresses
    echo "Getting IP addresses from OpenTofu output..."
    local debian_ips=$(get_ips_from_tofu)
    
    if [ -z "$debian_ips" ]; then
        echo "Error: No IP addresses found" >&2
        exit 1
    fi
    
    local ip_count=$(echo "$debian_ips" | wc -l)
    echo "Found $ip_count IP addresses to process"
    echo ""
    
    # Test credentials on first IP
    local first_ip=$(echo "$debian_ips" | head -n1)
    echo "Testing whiteteam credentials on first host ($first_ip)..."
    if ! test_whiteteam_credentials "$first_ip"; then
        echo "Error: whiteteam:whiteteam credentials don't work. Cannot proceed."
        exit 1
    fi
    echo ""
    
    # Process each IP with threading
    echo "Writing status based on current score files (using up to $MAX_THREADS threads)..."
    local success_count=0
    local failed_count=0
    
    # Convert to array to avoid here string issues
    local ip_array=()
    while IFS= read -r ip; do
        ip_array+=("$ip")
    done <<< "$debian_ips"
    
    # Clean up old result files
    rm -f /tmp/results_*.tmp
    
    local processed_count=0
    local thread_id=1
    
    for ip in "${ip_array[@]}"; do
        ((processed_count++))
        
        # Start background process for this IP
        write_status_to_remote_threaded "$ip" "$thread_id" &
        
        # Increment thread ID for next use
        ((thread_id++))
        
        # Limit concurrent processes
        while (( $(jobs -r | wc -l) >= MAX_THREADS )); do
            sleep 0.1
        done
        
        # Show progress for large numbers of hosts
        if (( processed_count % 10 == 0 )); then
            echo "Progress: $processed_count/$ip_count hosts started"
        fi
        
        # Small delay to stagger connection attempts
        sleep 0.1
    done
    
    # Wait for all background jobs to complete
    echo "Waiting for all $processed_count SCP operations to complete..."
    wait
    
    # Collect results from all thread result files
    for result_file in /tmp/results_*.tmp; do
        if [ -f "$result_file" ]; then
            while IFS=: read -r ip status; do
                if [ "$status" = "SUCCESS" ]; then
                    ((success_count++))
                else
                    ((failed_count++))
                fi
            done < "$result_file"
        fi
    done
    
    # Clean up result files
    rm -f /tmp/results_*.tmp
    
    # Display summary
    echo ""
    echo "============================================="
    echo "STATUS WRITER SUMMARY"
    echo "============================================="
    echo "Total hosts: $ip_count"
    echo "Successfully updated: $success_count"
    echo "Failed: $failed_count"
    echo ""
    echo "Status file location on each host: $STATUS_FILE"
    echo "Detailed logs in: $LOG_FILE"
    echo "SCP status tracking: $SCP_STATUS_FILE"
    echo ""
    echo "Score file timestamps:"
    echo "  Database: $(stat -c %y "$CURL_SCORE_FILE" 2>/dev/null || echo "Not found")"
    echo "  SSH: $(stat -c %y "$SSH_SCORE_FILE" 2>/dev/null || echo "Not found")"
    echo "[$(date '+%H:%M:%S')] CTF Whiteteam Status Writer Completed" >> "$LOG_FILE"
    
    # Clean up temporary score files
    cleanup_score_copies
}

# Function to verify status files were written (read back from hosts)
verify_status_files() {
    echo "============================================="
    echo "VERIFYING STATUS FILES ON REMOTE HOSTS"
    echo "============================================="
    
    local debian_ips=$(get_ips_from_tofu)
    local verification_count=0
    local verification_success=0
    
    while IFS= read -r ip; do
        echo "Checking $STATUS_FILE on $ip..."
        local verification_result=$(timeout $SSH_TIMEOUT sshpass -p "whiteteam" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=yes -o PubkeyAuthentication=no whiteteam@$ip "ls -la $STATUS_FILE && echo '=== FILE CONTENT ===' && head -n 10 $STATUS_FILE" 2>/dev/null)
        local verification_exit_code=$?
        
        ((verification_count++))
        
        if [[ $verification_exit_code -eq 0 ]] && [[ "$verification_result" =~ "SYSTEM STATUS REPORT" ]]; then
            echo "✓ $ip - Status file exists and contains expected content"
            ((verification_success++))
        else
            echo "✗ $ip - Status file verification failed"
        fi
        echo ""
    done <<< "$debian_ips"
    
    echo "Verification complete: $verification_success/$verification_count hosts have valid status files"
}

# Function to display SCP status summary
show_scp_status_summary() {
    if [ -f "$SCP_STATUS_FILE" ]; then
        echo "============================================="
        echo "SCP STATUS SUMMARY"
        echo "============================================="
        echo "SCP Status file: $SCP_STATUS_FILE"
        echo "Generated: $(head -n1 "$SCP_STATUS_FILE" | sed 's/# SCP Status Report - //')"
        echo ""
        
        local total_attempts=$(grep -v "^#" "$SCP_STATUS_FILE" | grep -v "^$" | wc -l)
        local successful=$(grep -v "^#" "$SCP_STATUS_FILE" | grep " SUCCESS " | wc -l)
        local failed=$(grep -v "^#" "$SCP_STATUS_FILE" | grep " FAILED " | wc -l)
        
        echo "Total SCP attempts: $total_attempts"
        echo "Successful: $successful"
        echo "Failed: $failed"
        echo ""
        echo "Failed hosts details:"
        grep -v "^#" "$SCP_STATUS_FILE" | grep " FAILED " | while read -r line; do
            local ip=$(echo "$line" | awk '{print $1}')
            local details=$(echo "$line" | awk '{print $4}')
            echo "  $ip - $details"
        done
        echo ""
        echo "Recent entries (last 10):"
        tail -n 10 "$SCP_STATUS_FILE" | grep -v "^#" | grep -v "^$"
    else
        echo "SCP status file not found: $SCP_STATUS_FILE"
    fi
}

# Handle command line arguments
case "${1:-wait-and-write}" in
    "write")
        # Use non-threaded version for compatibility (no waiting)
        echo "Using sequential mode (no threading, no waiting)"
        
        # Check if score files exist
        local missing_files=()
        if [ ! -f "$CURL_SCORE_FILE" ]; then
            missing_files+=("$CURL_SCORE_FILE")
        fi
        if [ ! -f "$SSH_SCORE_FILE" ]; then
            missing_files+=("$SSH_SCORE_FILE")
        fi
        
        if [ ${#missing_files[@]} -gt 0 ]; then
            echo "Warning: Missing score files: ${missing_files[*]}"
            echo "The script will still run but will show 'NO_DATA' for missing scores."
            echo ""
        fi
        
        # Initialize log file without waiting
        echo "[$(date '+%H:%M:%S')] CTF Whiteteam Status Writer Started (Score Reader Mode - No Wait)" > "$LOG_FILE"
        
        # Skip the wait_for_score_files call and run the rest of main
        check_dependencies
        echo "✓ All dependencies available"
        echo ""
        
        # Get IP addresses and continue with rest of main function logic
        echo "Getting IP addresses from OpenTofu output..."
        local debian_ips=$(get_ips_from_tofu)
        
        if [ -z "$debian_ips" ]; then
            echo "Error: No IP addresses found" >&2
            exit 1
        fi
        
        # Copy score files to temporary locations for stable reading
        echo "Creating stable copies of available score files..."
        copy_score_files
        echo ""
        
        local ip_count=$(echo "$debian_ips" | wc -l)
        echo "Found $ip_count IP addresses to process"
        echo ""
        
        # Test credentials on first IP
        local first_ip=$(echo "$debian_ips" | head -n1)
        echo "Testing whiteteam credentials on first host ($first_ip)..."
        if ! test_whiteteam_credentials "$first_ip"; then
            echo "Error: whiteteam:whiteteam credentials don't work. Cannot proceed."
            exit 1
        fi
        echo ""
        
        # Process each IP without threading
        echo "Writing status based on current score files (sequential)..."
        local success_count=0
        local failed_count=0
        
        while IFS= read -r ip; do
            if write_status_to_remote "$ip"; then
                ((success_count++))
            else
                ((failed_count++))
            fi
        done <<< "$debian_ips"
        
        # Display summary
        echo ""
        echo "============================================="
        echo "STATUS WRITER SUMMARY"
        echo "============================================="
        echo "Total hosts: $ip_count"
        echo "Successfully updated: $success_count"
        echo "Failed: $failed_count"
        echo ""
        echo "Status file location on each host: $STATUS_FILE"
        echo "Detailed logs in: $LOG_FILE"
        echo ""
        echo "Score file timestamps:"
        echo "  Database: $(stat -c %y "$CURL_SCORE_FILE" 2>/dev/null || echo "Not found")"
        echo "  SSH: $(stat -c %y "$SSH_SCORE_FILE" 2>/dev/null || echo "Not found")"
        echo "[$(date '+%H:%M:%S')] CTF Whiteteam Status Writer Completed" >> "$LOG_FILE"
        
        # Clean up temporary score files
        cleanup_score_copies
        ;;
    "write-threaded")
        echo "Using threaded mode with $MAX_THREADS max threads (no waiting)"
        
        # Check if score files exist
        local missing_files=()
        if [ ! -f "$CURL_SCORE_FILE" ]; then
            missing_files+=("$CURL_SCORE_FILE")
        fi
        if [ ! -f "$SSH_SCORE_FILE" ]; then
            missing_files+=("$SSH_SCORE_FILE")
        fi
        
        if [ ${#missing_files[@]} -gt 0 ]; then
            echo "Warning: Missing score files: ${missing_files[*]}"
            echo "The script will still run but will show 'NO_DATA' for missing scores."
            echo ""
        fi
        
        # Initialize log file and SCP status file without waiting
        echo "[$(date '+%H:%M:%S')] CTF Whiteteam Status Writer Started (Score Reader Mode - No Wait)" > "$LOG_FILE"
        init_scp_status_file
        
        # Run main without the wait_for_score_files call
        check_dependencies
        echo "✓ All dependencies available"
        echo ""
        
        # Get IP addresses and continue with rest of main function logic
        echo "Getting IP addresses from OpenTofu output..."
        local debian_ips=$(get_ips_from_tofu)
        
        if [ -z "$debian_ips" ]; then
            echo "Error: No IP addresses found" >&2
            exit 1
        fi
        
        # Copy score files to temporary locations for stable reading
        echo "Creating stable copies of available score files..."
        copy_score_files
        echo ""
        
        local ip_count=$(echo "$debian_ips" | wc -l)
        echo "Found $ip_count IP addresses to process"
        echo ""
        
        # Test credentials on first IP
        local first_ip=$(echo "$debian_ips" | head -n1)
        echo "Testing whiteteam credentials on first host ($first_ip)..."
        if ! test_whiteteam_credentials "$first_ip"; then
            echo "Error: whiteteam:whiteteam credentials don't work. Cannot proceed."
            exit 1
        fi
        echo ""
        
        # Process each IP with threading (rest of original main function)
        echo "Writing status based on current score files (using up to $MAX_THREADS threads)..."
        local success_count=0
        local failed_count=0
        
        # Convert to array to avoid here string issues
        local ip_array=()
        while IFS= read -r ip; do
            ip_array+=("$ip")
        done <<< "$debian_ips"
        
        # Clean up old result files
        rm -f /tmp/results_*.tmp
        
        local processed_count=0
        local thread_id=1
        
        for ip in "${ip_array[@]}"; do
            ((processed_count++))
            
            # Start background process for this IP
            write_status_to_remote_threaded "$ip" "$thread_id" &
            
            # Increment thread ID for next use
            ((thread_id++))
            
            # Limit concurrent processes
            while (( $(jobs -r | wc -l) >= MAX_THREADS )); do
                sleep 0.1
            done
            
            # Show progress for large numbers of hosts
            if (( processed_count % 10 == 0 )); then
                echo "Progress: $processed_count/$ip_count hosts started"
            fi
            
            # Small delay to stagger connection attempts
            sleep 0.1
        done
        
        # Wait for all background jobs to complete
        echo "Waiting for all $processed_count SCP operations to complete..."
        wait
        
        # Collect results from all thread result files
        for result_file in /tmp/results_*.tmp; do
            if [ -f "$result_file" ]; then
                while IFS=: read -r ip status; do
                    if [ "$status" = "SUCCESS" ]; then
                        ((success_count++))
                    else
                        ((failed_count++))
                    fi
                done < "$result_file"
            fi
        done
        
        # Clean up result files
        rm -f /tmp/results_*.tmp
        
        # Display summary
        echo ""
        echo "============================================="
        echo "STATUS WRITER SUMMARY"
        echo "============================================="
        echo "Total hosts: $ip_count"
        echo "Successfully updated: $success_count"
        echo "Failed: $failed_count"
        echo ""
        echo "Status file location on each host: $STATUS_FILE"
        echo "Detailed logs in: $LOG_FILE"
        echo "SCP status tracking: $SCP_STATUS_FILE"
        echo ""
        echo "Score file timestamps:"
        echo "  Database: $(stat -c %y "$CURL_SCORE_FILE" 2>/dev/null || echo "Not found")"
        echo "  SSH: $(stat -c %y "$SSH_SCORE_FILE" 2>/dev/null || echo "Not found")"
        echo "[$(date '+%H:%M:%S')] CTF Whiteteam Status Writer Completed" >> "$LOG_FILE"
        
        # Clean up temporary score files
        cleanup_score_copies
        ;;
    "wait-and-write")
        echo "Using threaded mode with $MAX_THREADS max threads (with waiting for score files)"
        main
        ;;
    "verify")
        check_dependencies
        verify_status_files
        ;;
    "test")
        check_dependencies
        debian_ips=$(get_ips_from_tofu)
        first_ip=$(echo "$debian_ips" | head -n1)
        echo "Testing whiteteam credentials on $first_ip..."
        test_whiteteam_credentials "$first_ip"
        ;;
    "status")
        echo "=== CURRENT SCORE FILE STATUS ==="
        echo "Database scores ($CURL_SCORE_FILE):"
        if [ -f "$CURL_SCORE_FILE" ]; then
            echo "  Last modified: $(stat -c %y "$CURL_SCORE_FILE")"
            echo "  Entries: $(wc -l < "$CURL_SCORE_FILE")"
            echo "  Sample: $(head -n 1 "$CURL_SCORE_FILE")"
        else
            echo "  File not found"
        fi
        echo ""
        echo "SSH scores ($SSH_SCORE_FILE):"
        if [ -f "$SSH_SCORE_FILE" ]; then
            echo "  Last modified: $(stat -c %y "$SSH_SCORE_FILE")"
            echo "  Entries: $(wc -l < "$SSH_SCORE_FILE")"
            echo "  Sample: $(head -n 1 "$SSH_SCORE_FILE")"
        else
            echo "  File not found"
        fi
        ;;
    "scp-status")
        show_scp_status_summary
        ;;
    *)
        echo "Usage: $0 [wait-and-write|write|write-threaded|verify|test|status|scp-status]"
        echo "  wait-and-write- Wait for score files to be ready, then write status (parallel, default)"
        echo "  write         - Write status once to all hosts (sequential, no waiting)"
        echo "  write-threaded- Write status once to all hosts (parallel, no waiting)"
        echo "  verify        - Verify status files exist on all hosts"
        echo "  test          - Test whiteteam credentials on first host"
        echo "  status        - Show current score file status"
        echo "  scp-status    - Show SCP success/failure tracking for dashboard"
        echo ""
        echo "Threading configuration: MAX_THREADS=$MAX_THREADS"
        echo "SCP status tracking file: $SCP_STATUS_FILE"
        echo "Waiting behavior:"
        echo "  - wait-and-write: Waits for score files to exist and be stable for 5 seconds"
        echo "  - write/write-threaded: Processes immediately with available files"
        echo ""
        echo "Examples:"
        echo "  $0                       # Wait for score files, then run with threading (default)"
        echo "  $0 wait-and-write        # Wait for score files, then run with threading"
        echo "  $0 write                 # Run immediately, sequentially"
        echo "  $0 write-threaded        # Run immediately with threading"
        echo "  $0 scp-status            # Show SCP tracking for dashboard"
        exit 1
        ;;
esac
