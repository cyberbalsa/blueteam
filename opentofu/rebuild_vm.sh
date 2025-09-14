#!/bin/bash

# Script to rebuild a Debian VM while keeping the same floating IP
# Usage: ./rebuild_vm.sh <floating_ip>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 <floating_ip>"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100"
    echo "  $0 10.0.0.50"
    echo ""
    echo "This script will:"
    echo "  1. Find the VM instance associated with the given floating IP"
    echo "  2. Destroy only that specific VM instance (keeping the floating IP)"
    echo "  3. Recreate the VM instance"
    echo "  4. Re-associate the same floating IP"
}

# Check if floating IP is provided
if [ $# -eq 0 ]; then
    print_error "No floating IP provided"
    show_usage
    exit 1
fi

FLOATING_IP="$1"

# Validate IP format (basic validation)
if ! [[ $FLOATING_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    print_error "Invalid IP format: $FLOATING_IP"
    show_usage
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "main.tf" ] || [ ! -f "instances.tf" ]; then
    print_error "This script must be run from the OpenTofu directory containing main.tf and instances.tf"
    exit 1
fi

print_status "Starting VM rebuild process for floating IP: $FLOATING_IP"

# Get current OpenTofu outputs to find the VM index
print_status "Getting current OpenTofu outputs..."
if ! tofu output -json > /tmp/tofu_outputs.json 2>/dev/null; then
    print_error "Failed to get OpenTofu outputs. Make sure the infrastructure is deployed."
    exit 1
fi

# Find the index of the VM with the given floating IP
DEBIAN_IPS=$(tofu output -json debian_vm_ips | jq -r '.[]')
VM_INDEX=-1
INDEX=0

for ip in $DEBIAN_IPS; do
    if [ "$ip" = "$FLOATING_IP" ]; then
        VM_INDEX=$INDEX
        break
    fi
    INDEX=$((INDEX + 1))
done

if [ $VM_INDEX -eq -1 ]; then
    print_error "No VM found with floating IP: $FLOATING_IP"
    print_status "Available floating IPs:"
    echo "$DEBIAN_IPS"
    exit 1
fi

print_success "Found VM at index $VM_INDEX with floating IP: $FLOATING_IP"

# Get VM name for confirmation
VM_NAME=$(tofu output -json debian_vm_names | jq -r ".[$VM_INDEX]")
print_status "VM Name: $VM_NAME"

# Confirmation prompt
echo ""
print_warning "This will destroy and recreate the following resources:"
echo "  - openstack_compute_instance_v2.debian[$VM_INDEX] ($VM_NAME)"
echo "  - openstack_networking_floatingip_associate_v2.debian_fip_assoc[$VM_INDEX]"
echo ""
echo "The floating IP ($FLOATING_IP) will be preserved and re-associated."
echo ""
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_status "Operation cancelled."
    exit 0
fi

print_status "Starting targeted destroy and recreate..."

# Step 2: Destroy the VM instance
print_status "Step 2/4: Destroying VM instance..."
if tofu destroy -target="openstack_compute_instance_v2.debian[$VM_INDEX]" -auto-approve; then
    print_success "VM instance destroyed"
else
    print_error "Failed to destroy VM instance"
    exit 1
fi

# Step 3: Recreate the VM instance
print_status "Step 3/4: Recreating VM instance..."
if tofu apply -target="openstack_compute_instance_v2.debian[$VM_INDEX]" -auto-approve; then
    print_success "VM instance recreated"
else
    print_error "Failed to recreate VM instance"
    exit 1
fi

# Step 4: Recreate the floating IP association
print_status "Step 4/4: Re-associating floating IP..."
if tofu apply -target="openstack_networking_floatingip_associate_v2.debian_fip_assoc[$VM_INDEX]" -auto-approve; then
    print_success "Floating IP re-associated"
else
    print_error "Failed to re-associate floating IP"
    exit 1
fi
tofu refresh
tofu apply -auto-approve
print_success "VM rebuild completed successfully!"
print_status "VM $VM_NAME has been rebuilt and is accessible at $FLOATING_IP"

# Optional: Show the new internal IP
NEW_INTERNAL_IP=$(tofu output -json debian_vm_internal_ips | jq -r ".[$VM_INDEX]")
print_status "New internal IP: $NEW_INTERNAL_IP"
print_status "Sleeping for 120 seconds to allow the VM to boot..."
bash ./makeinv.sh
sleep 120
cd ../ansible
ansible-playbook nginx-php-crud-api.yml ssh-blank-password.yml --limit "$VM_NAME"