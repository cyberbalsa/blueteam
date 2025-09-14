# Nginx PHP-CRUD-API Playbook

This Ansible playbook sets up nginx-full with nginx-lua and php-crud-api on Debian Trixie systems, configured to serve the USGS Lower US SQLite database.

## Overview

The playbook performs the following tasks:
- Installs nginx-full with lua module support
- Installs PHP 8.2 with required extensions for SQLite
- Downloads the single-file php-crud-api directly from GitHub
- Downloads the USGS Lower US SQLite database
- Configures nginx to serve the API with lua logging
- Sets up proper permissions and security headers

## Prerequisites

- Ansible 2.9+ installed on the control machine
- SSH access to all target Debian VMs
- Internet access on target machines for downloading packages, API file, and database
- Target machines running Debian Trixie

## Target Hosts

The playbook targets the `debian_vms` host group which includes 30 Debian virtual machines as defined in `inventory.ini`.

## Usage

### Basic Execution

```bash
# Run the complete playbook
ansible-playbook nginx-php-crud-api.yml

# Run with verbose output
ansible-playbook nginx-php-crud-api.yml -v

# Run specific tags only
ansible-playbook nginx-php-crud-api.yml --tags nginx,php

# Dry run to see what would be changed
ansible-playbook nginx-php-crud-api.yml --check
```

### Available Tags

- `packages`: Install system packages
- `nginx`: Install and configure nginx
- `php`: Install and configure PHP
- `directories`: Create required directories
- `database`: Download USGS database
- `api`: Download and configure php-crud-api
- `test`: Create test endpoints

### Running Specific Sections

```bash
# Install only nginx and PHP
ansible-playbook nginx-php-crud-api.yml --tags nginx,php

# Configure only the API components
ansible-playbook nginx-php-crud-api.yml --tags api,database

# Set up directories and download database only
ansible-playbook nginx-php-crud-api.yml --tags directories,database
```

## What Gets Installed

### Nginx Configuration
- **Package**: nginx-full with libnginx-mod-http-lua
- **Config**: Custom site configuration with lua logging
- **Location**: `/etc/nginx/sites-available/php-crud-api`
- **Document Root**: `/var/www/api`

### PHP Configuration
- **Version**: PHP 8.2 with FPM
- **Extensions**: sqlite3, json, mbstring, curl, xml, gd, zip, intl
- **Socket**: `/run/php/php8.2-fpm.sock`

### API Setup
- **Source**: https://raw.githubusercontent.com/mevdschee/php-crud-api/main/api.php
- **Location**: `/var/www/api`
- **Database**: USGS Lower US SQLite database
- **Type**: Single-file PHP application

### Database
- **Source**: http://2016.padjo.org/files/data/starterpack/usgs/usgs-lower-us.sqlite
- **Location**: `/var/www/api/database/usgs-lower-us.sqlite`
- **Type**: SQLite3
- **Contents**: USGS geographical data for the lower United States

## API Endpoints

After successful deployment, the following endpoints will be available:

### Test Endpoint
```bash
curl http://[server-ip]/test.php
```

Expected response:
```json
{
    "status": "success",
    "message": "php-crud-api is running",
    "database": "connected",
    "timestamp": "2025-09-13 10:30:45"
}
```

### API Documentation
```bash
# OpenAPI documentation
curl http://[server-ip]/openapi

# List all available tables
curl http://[server-ip]/records
```

### Sample API Calls
```bash
# Get table structure (replace 'tablename' with actual table name)
curl http://[server-ip]/records/[tablename]

# Get records with limit
curl http://[server-ip]/records/[tablename]?page=1,10

# Get specific record by ID
curl http://[server-ip]/records/[tablename]/1
```

## Security Features

The nginx configuration includes:
- **Security Headers**: X-Frame-Options, X-XSS-Protection, X-Content-Type-Options
- **CORS Support**: Configured for cross-origin requests
- **Access Logging**: Lua-based request logging
- **File Access Control**: Restricted access to sensitive files

## Troubleshooting

### Check Service Status
```bash
# On target machines
sudo systemctl status nginx
sudo systemctl status php8.2-fpm

# Check nginx configuration
sudo nginx -t

# Check PHP-FPM configuration
sudo php-fpm8.2 -t
```

### Common Issues

1. **Database not found**
   - Check if the database was downloaded: `ls -la /var/www/api/database/`
   - Verify internet connectivity during playbook execution

2. **PHP errors**
   - Check PHP-FPM logs: `sudo journalctl -u php8.2-fpm`
   - Verify PHP extensions: `php -m | grep sqlite`

3. **Nginx issues**
   - Check nginx error logs: `sudo tail -f /var/log/nginx/error.log`
   - Verify site is enabled: `ls -la /etc/nginx/sites-enabled/`

4. **Permission issues**
   - Verify file ownership: `ls -la /var/www/api/`
   - Should be owned by `www-data:www-data`

### Log Locations
- **Nginx Access**: `/var/log/nginx/access.log`
- **Nginx Error**: `/var/log/nginx/error.log`
- **PHP-FPM**: `journalctl -u php8.2-fpm`

## Customization

### Changing Database
To use a different SQLite database, modify the variables in the playbook:

```yaml
vars:
  usgs_db_url: "http://your-database-url.com/database.sqlite"
  usgs_db_file: "your-database.sqlite"
```

### API Configuration
The API configuration can be modified in the "Create API configuration file" task. Key settings:
- **CORS settings**: Modify `cors.allowOrigin`, `cors.allowMethods`
- **Controllers**: Enable/disable `records`, `geojson`, `openapi`
- **Debug mode**: Set `debug` to `true` for development

### Nginx Configuration
The nginx configuration can be customized in the "Create nginx site configuration" task:
- **SSL/TLS**: Add SSL certificate configuration
- **Domain name**: Change `server_name` from `_` to your domain
- **Additional locations**: Add custom location blocks

## Files Created

```
/var/www/api/
├── index.php              # Main API entry point
├── api.php               # Single-file php-crud-api
├── test.php              # Test endpoint
└── database/
    └── usgs-lower-us.sqlite  # USGS database

/etc/nginx/sites-available/
└── php-crud-api          # Nginx site configuration

/etc/nginx/sites-enabled/
└── php-crud-api -> ../sites-available/php-crud-api
```

## Validation

The playbook includes ansible-lint validation and has been tested to ensure:
- ✅ FQCN module names are used
- ✅ Proper YAML formatting
- ✅ Security best practices
- ✅ Idempotent operations
- ✅ Handler naming conventions

## License

This playbook is provided as-is for educational and deployment purposes.