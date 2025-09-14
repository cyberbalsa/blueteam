terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = ">= 1.52.1"
    }
  }
}

# READ THIS: https://search.opentofu.org/provider/terraform-provider-openstack/openstack/latest
# IMPORTANT: Replace the application_credential_id and application_credential_secret 
# with your own credentials downloaded from the OpenStack dashboard
provider "openstack" {
  auth_url                        = "https://openstack.cyberrange.rit.edu:5000/v3"
  region                         = "CyberRange"
  
  # TODO: Replace these with YOUR application credentials from OpenStack dashboard
  # Navigate to: Identity → Application Credentials
  application_credential_id      = "e59a24d6b4b84d9abef463c69bc154b3"
  application_credential_secret  = "7zFsVBVKc3IMULqitWArsPoFt-qYpQll_nNtbLQCVRfzhtn6s_x617Nf0FnLf6U6_oIoh6UPOmvu4nZazserQQ"
}
