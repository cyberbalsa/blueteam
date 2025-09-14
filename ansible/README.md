# CDT Domain Setup with Ansible

This Ansible project sets up a complete Active Directory domain called "CDT" with Windows and Linux servers.

## Infrastructure Overview

- **Domain Controller**: 10.10.10.21 (Windows)
- **Windows Members**: 10.10.10.22, 10.10.10.23
- **Linux Members**: 10.10.10.31, 10.10.10.32, 10.10.10.33
- **Domain**: CDT.local

## Prerequisites

1. All Windows servers should have WinRM enabled
2. All Linux servers should have SSH access as root
3. Update passwords in `inventory.ini` if different from defaults

## Usage

### Run Complete Setup
```bash
ansible-playbook -i inventory.ini site.yml
```

### Run Individual Components
```bash
# Setup domain controller only
ansible-playbook -i inventory.ini setup-domain-controller.yml

# Join Windows servers to domain
ansible-playbook -i inventory.ini join-windows-domain.yml

# Join Linux servers to domain  
ansible-playbook -i inventory.ini join-linux-domain.yml

# Create users and configure SSH
ansible-playbook -i inventory.ini create-domain-users.yml
```

## Created Users

The following domain users are created with password `UserPass123!`:
- `jdoe` (John Doe) - Linux Admin
- `asmith` (Alice Smith) - Linux Admin  
- `bwilson` (Bob Wilson)
- `mjohnson` (Mary Johnson)
- `dlee` (David Lee)

## SSH Access

Users can SSH to Linux boxes using their domain credentials:
```bash
ssh jdoe@CDT.local@10.10.10.31
# Password: UserPass123!
```

Linux Admins (jdoe, asmith) have sudo access without password.

## Security Groups

- **SSH Users**: All created users, allows SSH access to Linux boxes
- **Linux Admins**: jdoe and asmith, provides sudo access

## Configuration Notes

- Password authentication is enabled for SSH
- Home directories are created automatically on first login
- SSSD is configured for AD authentication on Linux boxes
- DNS is configured to use the domain controller

## Troubleshooting

### Check domain join status on Linux:
```bash
realm list
id jdoe@CDT.local
```

### Check SSH configuration:
```bash
sshd -t
systemctl status sssd
```

### Check Windows domain membership:
```powershell
Get-ComputerInfo | Select-Object WindowsDomainName
```