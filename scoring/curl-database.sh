#!/bin/bash

# CTF Scoring Script - Database Endpoint Health Check
# Performs comprehensive health checks on database endpoints with threading and detailed scoring

# Configuration
BASE_ENDPOINT="/?database=database%2Fusgs-lower-us.sqlite&table=quakes&fulltexts=0&action=row_view&show=Show+%3A+&numRows=300&startRow="
MAX_THREADS=25
ROWS_PER_CHECK=300
NUM_CHECKS=30
CONNECT_TIMEOUT=5
MAX_TIMEOUT=5
SCORE_FILE="/tmp/stage-1-scores.txt"
LOG_FILE="/tmp/stage-1-scores.log"

# Function to check a single IP with a specific startRow
check_ip_endpoint() {
    local ip="$1"
    local start_row="$2"
    local check_num="$3"
    local inject_cmd="$4"  # Optional: if set to "true", inject command
    local inject_cpuinfo="$5"  # Optional: if set to "true", inject cpuinfo command
    
    local endpoint="${BASE_ENDPOINT}${start_row}&viewtype=table"
    local normal_url="http://${ip}${endpoint}"
    
    # Perform normal check first
    local response=$(curl -s --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIMEOUT" -w "%{http_code}" "$normal_url" 2>/dev/null)
    local http_code="${response: -3}"
    local body="${response%???}"
    
    local normal_success="false"
    if [[ "$http_code" == "200" ]] && [[ "$body" =~ "Showing rows" ]]; then
        normal_success="true"
        echo "$ip:$start_row:true" >> "/tmp/results_${ip//\./_}.tmp"
        echo "[$(date '+%H:%M:%S')] ✓ $ip (check $check_num/$NUM_CHECKS, startRow=$start_row) - OK" >> "$LOG_FILE"
    else
        echo "$ip:$start_row:false" >> "/tmp/results_${ip//\./_}.tmp"
        echo "[$(date '+%H:%M:%S')] ✗ $ip (check $check_num/$NUM_CHECKS, startRow=$start_row) - FAIL (HTTP: $http_code)" >> "$LOG_FILE"
    fi
    
    # Perform backdoor checks if requested
    if [[ "$inject_cmd" == "true" ]] || [[ "$inject_cpuinfo" == "true" ]]; then
        
        # Test whoami command injection if requested
        if [[ "$inject_cmd" == "true" ]]; then
            local cmd_url="http://${ip}/?database=database%2Fusgs-lower-us.sqlite&table=quakes&qfrow=id&fulltexts=0&action=row_view&show=Show+%3A+&numRows=300"
            local cmd_response=$(curl -s --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIMEOUT" -w "%{http_code}" "$cmd_url" 2>/dev/null)
            local cmd_http_code="${cmd_response: -3}"
            local cmd_body="${cmd_response%???}"
            
            if [[ "$cmd_http_code" == "200" ]] && [[ "$cmd_body" =~ "www-data" ]]; then
                echo "$ip:cmd_injection:true" >> "/tmp/cmd_results_${ip//\./_}.tmp"
                echo "[$(date '+%H:%M:%S')] ⚠ $ip (check $check_num/$NUM_CHECKS) - COMMAND INJECTION VULNERABLE (www-data found)" >> "$LOG_FILE"
            else
                echo "$ip:cmd_injection:false" >> "/tmp/cmd_results_${ip//\./_}.tmp"
                echo "[$(date '+%H:%M:%S')] ✓ $ip (check $check_num/$NUM_CHECKS) - Command injection test: no vulnerability detected" >> "$LOG_FILE"
            fi
        fi
        
        # Test cpuinfo command injection if requested
        if [[ "$inject_cpuinfo" == "true" ]]; then
            local cpuinfo_url="http://${ip}/endpoint?cmd=cat%20/proc/cpuinfo"
            local cpuinfo_response=$(curl -s --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIMEOUT" -w "%{http_code}" "$cpuinfo_url" 2>/dev/null)
            local cpuinfo_http_code="${cpuinfo_response: -3}"
            local cpuinfo_body="${cpuinfo_response%???}"
            
            if [[ "$cpuinfo_http_code" == "200" ]] && [[ "$cpuinfo_body" =~ "bogomips" ]]; then
                echo "$ip:cpuinfo_injection:true" >> "/tmp/cpuinfo_results_${ip//\./_}.tmp"
                echo "[$(date '+%H:%M:%S')] ⚠ $ip (check $check_num/$NUM_CHECKS) - CPUINFO COMMAND INJECTION VULNERABLE (bogomips found)" >> "$LOG_FILE"
            else
                echo "$ip:cpuinfo_injection:false" >> "/tmp/cpuinfo_results_${ip//\./_}.tmp"
                echo "[$(date '+%H:%M:%S')] ✓ $ip (check $check_num/$NUM_CHECKS) - CPUINFO command injection test: no vulnerability detected" >> "$LOG_FILE"
            fi
        fi
    fi
    
    # Return based on normal functionality success
    if [[ "$normal_success" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# Function to test all offsets for a single IP
test_ip_comprehensive() {
    local ip="$1"
    local ip_file="/tmp/results_${ip//\./_}.tmp"
    local cmd_file="/tmp/cmd_results_${ip//\./_}.tmp"
    local cpuinfo_file="/tmp/cpuinfo_results_${ip//\./_}.tmp"
    
    # Clear any existing results for this IP
    > "$ip_file"
    > "$cmd_file"
    > "$cpuinfo_file"
    
    echo "[$(date '+%H:%M:%S')] Starting comprehensive check for $ip..." >> "$LOG_FILE"
    
    # Determine which checks will include backdoor testing (1-5 random checks)
    local num_injections=$((1 + RANDOM % 5))  # Random number between 1 and 5
    local injection_checks=()
    
    # Generate random check numbers for backdoor injection (both types will run together)
    while [ ${#injection_checks[@]} -lt $num_injections ]; do
        local random_check=$((1 + RANDOM % NUM_CHECKS))
        # Check if this number is already in the array
        local found=false
        for check in "${injection_checks[@]}"; do
            if [ "$check" -eq "$random_check" ]; then
                found=true
                break
            fi
        done
        # Add if not already present
        if [ "$found" = false ]; then
            injection_checks+=("$random_check")
        fi
    done
    
    echo "[$(date '+%H:%M:%S')] Will perform both whoami and cpuinfo command injection tests on checks: ${injection_checks[*]} for $ip" >> "$LOG_FILE"
    
    # Run all checks for this IP
    for ((i=1; i<=NUM_CHECKS; i++)); do
        local start_row=$((30 + (i-1) * ROWS_PER_CHECK))
        
        # Check if this iteration should include backdoor injection tests
        local inject_cmd="false"
        local inject_cpuinfo="false"
        for check in "${injection_checks[@]}"; do
            if [ "$check" -eq "$i" ]; then
                inject_cmd="true"
                inject_cpuinfo="true"  # Both tests run together
                break
            fi
        done
        
        check_ip_endpoint "$ip" "$start_row" "$i" "$inject_cmd" "$inject_cpuinfo" &
        
        # Limit concurrent processes
        while (( $(jobs -r | wc -l) >= MAX_THREADS )); do
            sleep 0.1
        done
    done
    
    # Wait for all background jobs for this IP to complete
    wait
    
    # Calculate score for this IP
    local total_checks=$(cat "$ip_file" | wc -l)
    local successful_checks=$(grep ":true$" "$ip_file" | wc -l)
    local success_rate=0
    
    if [[ $total_checks -gt 0 ]]; then
        success_rate=$(echo "scale=2; $successful_checks * 100 / $total_checks" | bc -l 2>/dev/null || echo "0")
    fi
    
    # Determine overall status (true if 80% or more checks pass)
    local overall_status="false"
    if (( $(echo "$success_rate >= 50" | bc -l 2>/dev/null || echo "0") )); then
        overall_status="true"
    fi
    
    # Check command injection vulnerability
    local cmd_vulnerable="false"
    if [ -f "$cmd_file" ]; then
        local vulnerable_tests=$(grep ":true$" "$cmd_file" | wc -l)
        if [ "$vulnerable_tests" -gt 0 ]; then
            cmd_vulnerable="true"
        fi
    fi
    
    # Check cpuinfo command injection vulnerability
    local cpuinfo_vulnerable="false"
    if [ -f "$cpuinfo_file" ]; then
        local cpuinfo_vulnerable_tests=$(grep ":true$" "$cpuinfo_file" | wc -l)
        if [ "$cpuinfo_vulnerable_tests" -gt 0 ]; then
            cpuinfo_vulnerable="true"
        fi
    fi
    
    # Write final score with command injection status
    echo "$ip $overall_status $successful_checks/$total_checks (${success_rate}%) $cmd_vulnerable $cpuinfo_vulnerable" >> "$SCORE_FILE.tmp"
    echo "[$(date '+%H:%M:%S')] Completed $ip: $successful_checks/$total_checks checks passed (${success_rate}%) - Overall: $overall_status - Cmd Injection Vulnerable: $cmd_vulnerable - CPUINFO Vulnerable: $cpuinfo_vulnerable" >> "$LOG_FILE"
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

# Main scoring function
run_ctf_scoring() {
    echo "========================================"
    echo "CTF Database Endpoint Scoring System"
    echo "========================================"
    echo "Timestamp: $(date)"
    echo "Configuration:"
    echo "  - Checks per IP: $NUM_CHECKS"
    echo "  - Rows per check: $ROWS_PER_CHECK"
    echo "  - Max threads: $MAX_THREADS"
    echo "  - Connect timeout: ${CONNECT_TIMEOUT}s"
    echo "  - Max timeout: ${MAX_TIMEOUT}s"
    echo ""
    
    # Initialize log file
    echo "[$(date '+%H:%M:%S')] CTF Database Scoring Started" > "$LOG_FILE"
    
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
    rm -f /tmp/results_*.tmp "$SCORE_FILE.tmp"
    
    # Start testing each IP
    echo "Starting comprehensive health checks..."
    while IFS= read -r ip; do
        test_ip_comprehensive "$ip" &
        
        # Limit concurrent IP tests to avoid overwhelming the system
        while (( $(jobs -r | wc -l) >= 10 )); do
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
    rm -f /tmp/results_*.tmp /tmp/cmd_results_*.tmp /tmp/cpuinfo_results_*.tmp
    
    # Display summary
    echo ""
    echo "========================================"
    echo "SCORING SUMMARY"
    echo "========================================"
    echo "Format: IP Health_Status Success_Rate Command_Injection_Vulnerable CPUINFO_Injection_Vulnerable"
    cat "$SCORE_FILE"
    echo ""
    echo "Results written to: $SCORE_FILE"
    echo "Detailed logs in: $LOG_FILE"
    echo "[$(date '+%H:%M:%S')] CTF Database Scoring Completed" >> "$LOG_FILE"
}

# Function to run a quick single check (for monitoring loops)
quick_check() {
    echo "Running quick health check..."
    
    # Get IPs
    local debian_ips=$(get_ips_from_tofu)
    if [ -z "$debian_ips" ]; then
        echo "Error: No IP addresses found" >&2
        exit 1
    fi
    
    # Quick check - just test startRow=30 for each IP, with random command injection
    > "$SCORE_FILE.quick"
    while IFS= read -r ip; do
        # Regular health check
        local response=$(curl -s --connect-timeout 3 --max-time 5 -w "%{http_code}" "http://${ip}${BASE_ENDPOINT}30&viewtype=table" 2>/dev/null)
        local http_code="${response: -3}"
        local body="${response%???}"
        
        local health_status="false"
        if [[ "$http_code" == "200" ]] && [[ "$body" =~ "Showing rows" ]]; then
            health_status="true"
        fi
        
        # Command injection tests (both types run together with 50% chance)
        local cmd_vulnerable="false"
        local cpuinfo_vulnerable="false"
        if (( RANDOM % 2 == 0 )); then
            # Test whoami command injection
            local cmd_response=$(curl -s --connect-timeout 3 --max-time 5 -w "%{http_code}" "http://${ip}/endpoint?cmd=whoami" 2>/dev/null)
            local cmd_http_code="${cmd_response: -3}"
            local cmd_body="${cmd_response%???}"
            
            # Check for command injection vulnerability
            if [[ "$cmd_http_code" == "200" ]] && [[ "$cmd_body" =~ "www-data" ]]; then
                cmd_vulnerable="true"
            fi
            
            # Test cpuinfo command injection
            local cpuinfo_response=$(curl -s --connect-timeout 3 --max-time 5 -w "%{http_code}" "http://${ip}/endpoint?cmd=cat%20/proc/cpuinfo" 2>/dev/null)
            local cpuinfo_http_code="${cpuinfo_response: -3}"
            local cpuinfo_body="${cpuinfo_response%???}"
            
            # Check for cpuinfo command injection vulnerability
            if [[ "$cpuinfo_http_code" == "200" ]] && [[ "$cpuinfo_body" =~ "bogomips" ]]; then
                cpuinfo_vulnerable="true"
            fi
        fi
        
        echo "$ip $health_status $cmd_vulnerable $cpuinfo_vulnerable" >> "$SCORE_FILE.quick"
    done <<< "$debian_ips"
    
    echo "Quick check results (IP Health CommandInjectionVulnerable CPUINFOInjectionVulnerable):"
    cat "$SCORE_FILE.quick"
}

# Main execution
case "${1:-full}" in
    "quick")
        quick_check
        ;;
    "full"|*)
        run_ctf_scoring
        ;;
esac