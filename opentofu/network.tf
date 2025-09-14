resource "openstack_networking_network_v2" "cdt_net" {
  name = var.network_name
}

resource "openstack_networking_subnet_v2" "cdt_subnet" {
  name            = "${var.network_name}-subnet"
  network_id      = openstack_networking_network_v2.cdt_net.id
  cidr            = var.subnet_cidr
  ip_version      = 4
  dns_nameservers = ["129.21.3.17", "129.21.4.18"]
}

resource "openstack_networking_router_v2" "cdt_router" {
  name                = var.router_name
  external_network_id = data.openstack_networking_network_v2.ext_net.id
}

resource "openstack_networking_router_interface_v2" "cdt_router_interface" {
  router_id = openstack_networking_router_v2.cdt_router.id
  subnet_id = openstack_networking_subnet_v2.cdt_subnet.id
}

data "openstack_networking_network_v2" "ext_net" {
  name = var.external_network
}
