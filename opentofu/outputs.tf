output "debian_vm_ips" {
  value = [for fip in openstack_networking_floatingip_v2.debian_fip : fip.address]
}

output "debian_vm_names" {
  value = [for vm in openstack_compute_instance_v2.debian : vm.name]
}

output "debian_vm_internal_ips" {
  value = [for vm in openstack_compute_instance_v2.debian : vm.access_ip_v4]
}
