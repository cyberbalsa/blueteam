#!/bin/bash

# CTF Scoring Script - SSH Backdoor Detection
# Performs comprehensive SSH backdoor checks with threading and detailed scoring

# Configuration
MAX_THREADS=50
SSH_TIMEOUT=5
SCORE_FILE="/tmp/ssh-backdoor-scores.txt"
LOG_FILE="/tmp/ssh-backdoor-scores.log"

# Function to check SSH backdoor as root user
check_root_backdoor() {
    local ip="$1"
    local check_num="$2"
    
    echo "[$(date '+%H:%M:%S')] Testing root SSH backdoor on $ip (check $check_num)" >> "$LOG_FILE"
    
    # Try to SSH as root and run cat /proc/cpuinfo
    local ssh_output=$(timeout $SSH_TIMEOUT ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o PubkeyAuthentication=yes -o BatchMode=yes root@$ip "cat /proc/cpuinfo" 2>/dev/null)
    local ssh_exit_code=$?
    
    # Check if SSH connection was successful and we got CPU info
    if [[ $ssh_exit_code -eq 0 ]] && [[ "$ssh_output" =~ "processor" ]] && [[ "$ssh_output" =~ "cpu" ]]; then
        # SSH backdoor detected - this is a security vulnerability
        echo "$ip:root_backdoor:true" >> "/tmp/root_backdoor_${ip//\./_}.tmp"
        echo "[$(date '+%H:%M:%S')] ⚠ $ip (check $check_num) - ROOT SSH BACKDOOR DETECTED (passwordless root access)" >> "$LOG_FILE"
        return 1  # Return 1 because this is a security issue
    else
        # No root backdoor detected - this is good
        echo "$ip:root_backdoor:false" >> "/tmp/root_backdoor_${ip//\./_}.tmp"
        echo "[$(date '+%H:%M:%S')] ✓ $ip (check $check_num) - Root SSH backdoor test: no vulnerability detected" >> "$LOG_FILE"
        return 0
    fi
}

# Function to check SSH backdoor as blueteam user with password
check_blueteam_backdoor() {
    local ip="$1"
    local check_num="$2"
    
    echo "[$(date '+%H:%M:%S')] Testing blueteam SSH backdoor on $ip (check $check_num)" >> "$LOG_FILE"
    
    # Use sshpass to try SSH with blueteam:blueteam credentials
    local ssh_output=""
    local ssh_exit_code=1
    
    # Check if sshpass is available
    if command -v sshpass >/dev/null 2>&1; then
        ssh_output=$(timeout $SSH_TIMEOUT sshpass -p "blueteam" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=yes -o PubkeyAuthentication=no blueteam@$ip "whoami && echo 'SSH_SUCCESS'" 2>/dev/null)
        ssh_exit_code=$?
    else
        # Fallback using expect if sshpass is not available
        ssh_output=$(timeout $SSH_TIMEOUT expect -c "
            set timeout $SSH_TIMEOUT
            spawn ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=yes -o PubkeyAuthentication=no blueteam@$ip \"whoami && echo 'SSH_SUCCESS'\"
            expect {
                \"password:\" {
                    send \"blueteam\r\"
                    expect {
                        \"SSH_SUCCESS\" {
                            puts \"blueteam\"
                            puts \"SSH_SUCCESS\"
                            exit 0
                        }
                        timeout { exit 1 }
                        eof { exit 1 }
                    }
                }
                timeout { exit 1 }
                eof { exit 1 }
            }
        " 2>/dev/null)
        ssh_exit_code=$?
    fi
    
    # Check if SSH connection was successful with blueteam credentials
    if [[ $ssh_exit_code -eq 0 ]] && [[ "$ssh_output" =~ "blueteam" ]] && [[ "$ssh_output" =~ "SSH_SUCCESS" ]]; then
        # Blueteam SSH backdoor detected - this is a security vulnerability
        echo "$ip:blueteam_backdoor:true" >> "/tmp/blueteam_backdoor_${ip//\./_}.tmp"
        echo "[$(date '+%H:%M:%S')] ⚠ $ip (check $check_num) - BLUETEAM SSH BACKDOOR DETECTED (blueteam:blueteam credentials work)" >> "$LOG_FILE"
        return 1  # Return 1 because this is a security issue
    else
        # No blueteam backdoor detected - this is good
        echo "$ip:blueteam_backdoor:false" >> "/tmp/blueteam_backdoor_${ip//\./_}.tmp"
        echo "[$(date '+%H:%M:%S')] ✓ $ip (check $check_num) - Blueteam SSH backdoor test: no vulnerability detected" >> "$LOG_FILE"
        return 0
    fi
}

# Function to test all SSH backdoors for a single IP
test_ip_ssh_backdoors() {
    local ip="$1"
    local root_file="/tmp/root_backdoor_${ip//\./_}.tmp"
    local blueteam_file="/tmp/blueteam_backdoor_${ip//\./_}.tmp"
    
    # Clear any existing results for this IP
    > "$root_file"
    > "$blueteam_file"
    
    echo "[$(date '+%H:%M:%S')] Starting SSH backdoor checks for $ip..." >> "$LOG_FILE"
    
    # Test root backdoor (multiple attempts to be thorough)
    for i in {1..3}; do
        check_root_backdoor "$ip" "root-$i" &
        
        # Limit concurrent processes
        while (( $(jobs -r | wc -l) >= MAX_THREADS )); do
            sleep 0.1
        done
    done
    
    # Test blueteam backdoor (multiple attempts to be thorough)
    for i in {1..3}; do
        check_blueteam_backdoor "$ip" "blueteam-$i" &
        
        # Limit concurrent processes
        while (( $(jobs -r | wc -l) >= MAX_THREADS )); do
            sleep 0.1
        done
    done
    
    # Wait for all background jobs for this IP to complete
    wait
    
    # Calculate results for this IP
    local root_vulnerable="false"
    local blueteam_vulnerable="false"
    
    # Check root backdoor results
    if [ -f "$root_file" ]; then
        local root_vulnerable_tests=$(grep ":true$" "$root_file" | wc -l)
        if [ "$root_vulnerable_tests" -gt 0 ]; then
            root_vulnerable="true"
        fi
    fi
    
    # Check blueteam backdoor results
    if [ -f "$blueteam_file" ]; then
        local blueteam_vulnerable_tests=$(grep ":true$" "$blueteam_file" | wc -l)
        if [ "$blueteam_vulnerable_tests" -gt 0 ]; then
            blueteam_vulnerable="true"
        fi
    fi
    
    # Determine overall security status (true means secure, false means vulnerable)
    local overall_secure="true"
    if [[ "$root_vulnerable" == "true" ]] || [[ "$blueteam_vulnerable" == "true" ]]; then
        overall_secure="false"
    fi
    
    # Write final score
    echo "$ip $overall_secure $root_vulnerable $blueteam_vulnerable" >> "$SCORE_FILE.tmp"
    echo "[$(date '+%H:%M:%S')] Completed $ip: Overall Secure: $overall_secure - Root Backdoor: $root_vulnerable - Blueteam Backdoor: $blueteam_vulnerable" >> "$LOG_FILE"
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

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for sshpass
    if ! command -v sshpass >/dev/null 2>&1; then
        missing_deps+=("sshpass")
    fi
    
    # Check for expect (backup for sshpass)
    if ! command -v expect >/dev/null 2>&1; then
        missing_deps+=("expect")
    fi
    
    # Check for jq
    if ! command -v jq >/dev/null 2>&1; then
        missing_deps+=("jq")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo "Warning: Missing dependencies: ${missing_deps[*]}"
        echo "Please install them with: sudo apt-get install ${missing_deps[*]}"
        
        # If both sshpass and expect are missing, we can't proceed
        if ! command -v sshpass >/dev/null 2>&1 && ! command -v expect >/dev/null 2>&1; then
            echo "Error: Either sshpass or expect is required for password authentication"
            exit 1
        fi
    fi
}

# Main scoring function
run_ssh_backdoor_scoring() {
    echo "========================================"
    echo "CTF SSH Backdoor Detection System"
    echo "========================================"
    echo "Timestamp: $(date)"
    echo "Configuration:"
    echo "  - SSH Timeout: ${SSH_TIMEOUT}s"
    echo "  - Max threads: $MAX_THREADS"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Initialize log file
    echo "[$(date '+%H:%M:%S')] CTF SSH Backdoor Scoring Started" > "$LOG_FILE"
    
    # Get IP addresses
    echo "Getting IP addresses from OpenTofu output..."
    local debian_ips=$(get_ips_from_tofu)
    
    if [ -z "$debian_ips" ]; then
        echo "Error: No IP addresses found" >&2
        exit 1
    fi
    
    local ip_count=$(echo "$debian_ips" | wc -l)
    echo "Found $ip_count IP addresses to test"
    echo ""
    
    # Clean up old files
    rm -f /tmp/*_backdoor_*.tmp  "$SCORE_FILE.tmp"
    
    # Start testing each IP
    echo "Starting SSH backdoor detection checks..."
    while IFS= read -r ip; do
        test_ip_ssh_backdoors "$ip" &
        
        # Limit concurrent IP tests to avoid overwhelming the system
        while (( $(jobs -r | wc -l) >= 50 )); do
            sleep 1
        done
    done <<< "$debian_ips"
    
    # Wait for all IP tests to complete
    echo "Waiting for all checks to complete..."
    wait
    
    # Finalize results
    if [ -f "$SCORE_FILE.tmp" ]; then
        # Sort results by IP for consistent output
        sort -V "$SCORE_FILE.tmp" > "$SCORE_FILE"
        rm -f "$SCORE_FILE.tmp"
    fi
    
    # Clean up temporary files
    rm -f /tmp/*_backdoor_*.tmp
    
    # Display summary
    echo ""
    echo "========================================"
    echo "SSH BACKDOOR DETECTION SUMMARY"
    echo "========================================"
    echo "Format: IP Overall_Secure Root_Backdoor_Detected Blueteam_Backdoor_Detected"
    echo "Legend: true = secure/detected, false = vulnerable/not detected"
    cat "$SCORE_FILE"
    echo ""
    echo "Results written to: $SCORE_FILE"
    echo "Detailed logs in: $LOG_FILE"
    echo "[$(date '+%H:%M:%S')] CTF SSH Backdoor Scoring Completed" >> "$LOG_FILE"
}

# Function to run a quick single check (for monitoring loops)
quick_ssh_check() {
    echo "Running quick SSH backdoor check..."
    
    # Get IPs
    local debian_ips=$(get_ips_from_tofu)
    if [ -z "$debian_ips" ]; then
        echo "Error: No IP addresses found" >&2
        exit 1
    fi
    
    # Quick check - single test for each backdoor type per IP
    > "$SCORE_FILE.quick"
    while IFS= read -r ip; do
        local root_vulnerable="false"
        local blueteam_vulnerable="false"
        
        # Quick root backdoor check
        local root_output=$(timeout $SSH_TIMEOUT ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o PubkeyAuthentication=yes -o BatchMode=yes root@$ip "echo 'ROOT_ACCESS'" 2>/dev/null)
        if [[ $? -eq 0 ]] && [[ "$root_output" =~ "ROOT_ACCESS" ]]; then
            root_vulnerable="true"
        fi
        
        # Quick blueteam backdoor check
        if command -v sshpass >/dev/null 2>&1; then
            local blueteam_output=$(timeout $SSH_TIMEOUT sshpass -p "blueteam" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=yes -o PubkeyAuthentication=no blueteam@$ip "echo 'BLUETEAM_ACCESS'" 2>/dev/null)
            if [[ $? -eq 0 ]] && [[ "$blueteam_output" =~ "BLUETEAM_ACCESS" ]]; then
                blueteam_vulnerable="true"
            fi
        fi
        
        # Determine overall security
        local overall_secure="true"
        if [[ "$root_vulnerable" == "true" ]] || [[ "$blueteam_vulnerable" == "true" ]]; then
            overall_secure="false"
        fi
        
        echo "$ip $overall_secure $root_vulnerable $blueteam_vulnerable" >> "$SCORE_FILE.quick"
    done <<< "$debian_ips"
    
    echo "Quick SSH check results (IP Overall_Secure Root_Backdoor Blueteam_Backdoor):"
    cat "$SCORE_FILE.quick"
}

# Main execution
case "${1:-full}" in
    "quick")
        quick_ssh_check
        ;;
    "full"|*)
        run_ssh_backdoor_scoring
        ;;
esac