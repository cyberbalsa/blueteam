data "openstack_images_image_v2" "windows" {
  name        = var.windows_image_name
  most_recent = true
}
data "openstack_images_image_v2" "debian" {
  name        = var.debian_image_name
  most_recent = true
}

resource "openstack_compute_instance_v2" "debian" {
  count       = var.debian_count
  name        = "cdt-debian-${count.index + 1}"
  image_name  = var.debian_image_name
  flavor_name = var.flavor_name
  key_pair    = var.keypair

  network {
    uuid = openstack_networking_network_v2.cdt_net.id
    fixed_ip_v4 = "10.10.10.1${count.index + 1}"
  }
  block_device {
     uuid                  = data.openstack_images_image_v2.debian.id
     source_type           = "image"
     volume_size           = 80
     destination_type      = "volume"
     delete_on_termination = true
  }
  user_data = file("${path.module}/debian-userdata.yaml")

  depends_on = [
  ]
}


resource "openstack_networking_floatingip_v2" "debian_fip" {
  count = var.debian_count
  pool  = var.external_network
}

data "openstack_networking_port_v2" "debian_port" {
  count      = var.debian_count
  device_id  = openstack_compute_instance_v2.debian[count.index].id
  network_id = openstack_networking_network_v2.cdt_net.id
}

resource "openstack_networking_floatingip_associate_v2" "debian_fip_assoc" {
  count       = var.debian_count
  floating_ip = openstack_networking_floatingip_v2.debian_fip[count.index].address
  port_id     = data.openstack_networking_port_v2.debian_port[count.index].id
}
