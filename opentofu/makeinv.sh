#!/bin/bash

# Generate Ansible inventory from tofu output
generate_inventory() {
    local output_file="/home/debian/blueteam/ansible/inventory.ini"
    rm -f "$output_file"
    # Get tofu output and extract debian_vm_ips array
    tofu_output=$(tofu output -json)

    # Extract IPs from debian_vm_ips array
    debian_ips=$(echo "$tofu_output" | jq -r '.debian_vm_ips.value[]')

    # Create inventory file
    cat > "$output_file" << EOF
[debian_vms]
EOF

    # Add each IP to the inventory
    counter=1
    while IFS= read -r ip; do
        echo "cdt-debian-${counter} ansible_host=${ip}" >> "$output_file"
        ((counter++))
    done <<< "$debian_ips"

    # Add group variables
    cat >> "$output_file" << EOF

[debian_vms:vars]
ansible_user=debian
ansible_become=yes
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

    echo "Inventory file created: $output_file"
}

# Run the function
generate_inventory "$1"
