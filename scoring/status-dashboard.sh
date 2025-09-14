#!/bin/bash

# CTF Status Dashboard Script
# Displays overall status from all scoring files with checkmarks for good status

# Configuration
STAGE1_FILE="/tmp/stage-1-scores.txt"
SSH_FILE="/tmp/ssh-backdoor-scores.txt"
SCP_FILE="/tmp/whiteteam-scp-status.txt"

# Unicode checkmarks and crosses
CHECK="✓"
CROSS="✗"
UNKNOWN="?"

# Colors
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Function to get database health status for an IP
get_database_health() {
    local ip="$1"
    
    if [ ! -f "$STAGE1_FILE" ]; then
        echo "$UNKNOWN"
        return
    fi
    
    # Format: IP Health_Status Success_Rate Command_Injection_Vulnerable CPUINFO_Injection_Vulnerable
    # Example: 100.65.1.20 true 30/30 (100.00%) true true
    local line
    line=$(grep "^$ip " "$STAGE1_FILE" 2>/dev/null)
    
    if [ -z "$line" ]; then
        echo "$UNKNOWN"
        return
    fi
    
    local health_status
    health_status=$(echo "$line" | awk '{print $2}')
    
    if [ "$health_status" = "true" ]; then
        echo -e "${GREEN}$CHECK${RESET}"
    else
        echo -e "${RED}$CROSS${RESET}"
    fi
}

# Function to get command injection status for an IP
get_injection_status() {
    local ip="$1"
    
    if [ ! -f "$STAGE1_FILE" ]; then
        echo "$UNKNOWN"
        return
    fi
    
    local line
    line=$(grep "^$ip " "$STAGE1_FILE" 2>/dev/null)
    
    if [ -z "$line" ]; then
        echo "$UNKNOWN"
        return
    fi
    
    local cmd_injection
    local cpuinfo_injection
    cmd_injection=$(echo "$line" | awk '{print $5}')
    cpuinfo_injection=$(echo "$line" | awk '{print $6}')
    
    # Both should be false for secure status (no backdoors)
    if [ "$cmd_injection" = "false" ] && [ "$cpuinfo_injection" = "false" ]; then
        echo -e "${GREEN}$CHECK${RESET}"
    else
        echo -e "${RED}$CROSS${RESET}"
    fi
}

# Function to get SSH backdoor status for an IP
get_ssh_backdoor_status() {
    local ip="$1"
    
    if [ ! -f "$SSH_FILE" ]; then
        echo "$UNKNOWN"
        return
    fi
    
    # Format: IP Overall_Secure Root_Backdoor_Detected Blueteam_Backdoor_Detected
    # Example: 100.65.1.20 false true true
    local line
    line=$(grep "^$ip " "$SSH_FILE" 2>/dev/null)
    
    if [ -z "$line" ]; then
        echo "$UNKNOWN"
        return
    fi
    
    local overall_secure
    overall_secure=$(echo "$line" | awk '{print $2}')
    
    # true means secure (no backdoors detected)
    if [ "$overall_secure" = "true" ]; then
        echo -e "${GREEN}$CHECK${RESET}"
    else
        echo -e "${RED}$CROSS${RESET}"
    fi
}

# Function to get SCP deployment status for an IP
get_scp_status() {
    local ip="$1"
    
    if [ ! -f "$SCP_FILE" ]; then
        echo "$UNKNOWN"
        return
    fi
    
    # Format: IP_ADDRESS STATUS TIMESTAMP DETAILS
    # Example: 100.65.2.8 SUCCESS 2025-09-14 20:11:26 Thread_1_SCP_successful
    local line
    line=$(grep "^$ip SUCCESS" "$SCP_FILE" 2>/dev/null)
    
    if [ -n "$line" ]; then
        echo -e "${GREEN}$CHECK${RESET}"
    else
        # Check if there's a FAILED entry
        local failed_line
        failed_line=$(grep "^$ip FAILED" "$SCP_FILE" 2>/dev/null)
        if [ -n "$failed_line" ]; then
            echo -e "${RED}$CROSS${RESET}"
        else
            echo -e "${YELLOW}$UNKNOWN${RESET}"
        fi
    fi
}

# Function to get all unique IPs from all score files
get_all_ips() {
    {
        [ -f "$STAGE1_FILE" ] && awk '{print $1}' "$STAGE1_FILE" 2>/dev/null
        [ -f "$SSH_FILE" ] && awk '{print $1}' "$SSH_FILE" 2>/dev/null
        [ -f "$SCP_FILE" ] && grep -v "^#" "$SCP_FILE" 2>/dev/null | grep -v "^$" | awk '{print $1}'
    } | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | uniq
}

# Function to get success rate for database
get_success_rate() {
    local ip="$1"
    
    if [ ! -f "$STAGE1_FILE" ]; then
        echo "N/A"
        return
    fi
    
    local line
    line=$(grep "^$ip " "$STAGE1_FILE" 2>/dev/null)
    
    if [ -z "$line" ]; then
        echo "N/A"
        return
    fi
    
    # Extract success rate (e.g., "30/30 (100.00%)")
    echo "$line" | awk '{print $3 " " $4}' | sed 's/[()]//g'
}

# Function to display detailed status for an IP
show_detailed_status() {
    local ip="$1"
    
    echo ""
    echo -e "${BLUE}=== Detailed Status for $ip ===${RESET}"
    
    # Database details
    if [ -f "$STAGE1_FILE" ]; then
        local stage1_line=$(grep "^$ip " "$STAGE1_FILE" 2>/dev/null)
        if [ -n "$stage1_line" ]; then
            local health=$(echo "$stage1_line" | awk '{print $2}')
            local rate=$(echo "$stage1_line" | awk '{print $3 " " $4}')
            local cmd_inj=$(echo "$stage1_line" | awk '{print $5}')
            local cpu_inj=$(echo "$stage1_line" | awk '{print $6}')
            
            echo "Database Health: $health"
            echo "Success Rate: $rate"
            echo "Command Injection Vulnerable: $cmd_inj"
            echo "CPU Info Injection Vulnerable: $cpu_inj"
        else
            echo "Database: No data available"
        fi
    fi
    
    # SSH details
    if [ -f "$SSH_FILE" ]; then
        local ssh_line=$(grep "^$ip " "$SSH_FILE" 2>/dev/null)
        if [ -n "$ssh_line" ]; then
            local secure=$(echo "$ssh_line" | awk '{print $2}')
            local root_backdoor=$(echo "$ssh_line" | awk '{print $3}')
            local blue_backdoor=$(echo "$ssh_line" | awk '{print $4}')
            
            echo "SSH Overall Secure: $secure"
            echo "Root Backdoor Detected: $root_backdoor"
            echo "Blueteam Backdoor Detected: $blue_backdoor"
        else
            echo "SSH: No data available"
        fi
    fi
    
    # SCP details
    if [ -f "$SCP_FILE" ]; then
        local scp_line=$(grep "^$ip " "$SCP_FILE" 2>/dev/null | tail -1)
        if [ -n "$scp_line" ]; then
            local status=$(echo "$scp_line" | awk '{print $2}')
            local timestamp=$(echo "$scp_line" | awk '{print $3 " " $4}')
            local details=$(echo "$scp_line" | awk '{for(i=5;i<=NF;i++) printf "%s ", $i; print ""}')
            
            echo "SCP Status: $status"
            echo "Last Updated: $timestamp"
            echo "Details: $details"
        else
            echo "SCP: No data available"
        fi
    fi
    
    echo ""
}

# Function to display summary statistics
show_summary() {
    local total_ips="$1"
    local healthy_db=0
    local secure_injection=0
    local secure_ssh=0
    local successful_scp=0
    
    echo ""
    echo -e "${BLUE}=== SUMMARY STATISTICS ===${RESET}"
    
    while IFS= read -r ip; do
        # Count healthy databases
        if [ -f "$STAGE1_FILE" ]; then
            local line=$(grep "^$ip " "$STAGE1_FILE" 2>/dev/null)
            if [ -n "$line" ]; then
                local health=$(echo "$line" | awk '{print $2}')
                [ "$health" = "true" ] && ((healthy_db++))
                
                local cmd_inj=$(echo "$line" | awk '{print $5}')
                local cpu_inj=$(echo "$line" | awk '{print $6}')
                [ "$cmd_inj" = "false" ] && [ "$cpu_inj" = "false" ] && ((secure_injection++))
            fi
        fi
        
        # Count secure SSH
        if [ -f "$SSH_FILE" ]; then
            local line=$(grep "^$ip " "$SSH_FILE" 2>/dev/null)
            if [ -n "$line" ]; then
                local secure=$(echo "$line" | awk '{print $2}')
                [ "$secure" = "true" ] && ((secure_ssh++))
            fi
        fi
        
        # Count successful SCP
        if [ -f "$SCP_FILE" ]; then
            local line=$(grep "^$ip SUCCESS" "$SCP_FILE" 2>/dev/null)
            [ -n "$line" ] && ((successful_scp++))
        fi
    done <<< "$total_ips"
    
    local total_count=$(echo "$total_ips" | wc -l)
    
    echo "Total Systems: $total_count"
    echo "Healthy Databases: $healthy_db/$total_count"
    echo "Secure from Injection: $secure_injection/$total_count"
    echo "Secure SSH: $secure_ssh/$total_count"
    echo "Successful Status Deployment: $successful_scp/$total_count"
    
    # Calculate overall health percentage
    local total_checks=$((total_count * 4))
    local passed_checks=$((healthy_db + secure_injection + secure_ssh + successful_scp))
    local health_percentage=0
    
    if [ $total_checks -gt 0 ]; then
        health_percentage=$(echo "scale=1; $passed_checks * 100 / $total_checks" | bc -l 2>/dev/null || echo "0")
    fi
    
    echo ""
    echo -e "Overall System Health: ${health_percentage}%"
    
    if (( $(echo "$health_percentage >= 80" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "${GREEN}Status: EXCELLENT${RESET}"
    elif (( $(echo "$health_percentage >= 60" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "${YELLOW}Status: GOOD${RESET}"
    elif (( $(echo "$health_percentage >= 40" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "${YELLOW}Status: NEEDS ATTENTION${RESET}"
    else
        echo -e "${RED}Status: CRITICAL${RESET}"
    fi
}

# Main dashboard function
show_dashboard() {
    clear
    echo "========================================================"
    echo "           CTF BLUE TEAM STATUS DASHBOARD"
    echo "========================================================"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "Legend:"
    echo -e "  ${GREEN}$CHECK${RESET} = Good/Secure    ${RED}$CROSS${RESET} = Bad/Vulnerable    ${YELLOW}$UNKNOWN${RESET} = Unknown/No Data"
    echo ""
    
    # Check if files exist
    local missing_files=()
    [ ! -f "$STAGE1_FILE" ] && missing_files+=("Database scores")
    [ ! -f "$SSH_FILE" ] && missing_files+=("SSH scores")
    [ ! -f "$SCP_FILE" ] && missing_files+=("SCP status")
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Missing files: ${missing_files[*]}${RESET}"
        echo ""
    fi
    
    # Get all IPs
    local all_ips
    all_ips=$(get_all_ips)
    
    if [ -z "$all_ips" ]; then
        echo -e "${RED}Error: No IP addresses found in any score files${RESET}"
        exit 1
    fi
    
    # Header
    echo "IP Address        Web Health          Web Injection        SSH Secure           White Team Status    Web Success Rate"
    echo "----------------+--------------------+--------------------+--------------------+--------------------+---------------------"
    
    # Display status for each IP
    while IFS= read -r ip; do
        local db_health=$(get_database_health "$ip")
        local injection_status=$(get_injection_status "$ip")
        local ssh_status=$(get_ssh_backdoor_status "$ip")
        local scp_status=$(get_scp_status "$ip")
        local success_rate=$(get_success_rate "$ip")
        
        printf "%-15s | %-29s | %-29s | %-29s | %-29s | %-29s\n" \
               "$ip" "$db_health" "$injection_status" "$ssh_status" "$scp_status" "$success_rate"
    done <<< "$all_ips"
    
    # Show summary
    #show_summary "$all_ips"
}

# Function to watch and auto-refresh
watch_dashboard() {
    while true; do
        show_dashboard
        echo ""
        echo "Auto-refreshing in 30 seconds... (Press Ctrl+C to stop)"
        sleep 30
    done
}

# Main execution
case "${1:-dashboard}" in
    "refresh"|"dashboard"|"")
        show_dashboard
        ;;
    "watch")
        watch_dashboard
        ;;
    *)
        # Assume it's an IP address for detailed view
        show_dashboard
        show_detailed_status "$1"
        ;;
esac