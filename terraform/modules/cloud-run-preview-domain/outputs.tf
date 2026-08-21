output "dns_records" {
  description = "DNS-only records required at the authoritative provider for wildcard routing and certificate authorization."
  value = {
    preview_wildcard = {
      name = local.wildcard_domain
      type = "A"
      data = google_compute_global_address.preview.address
    }
    certificate_authorization = {
      name = google_certificate_manager_dns_authorization.preview.dns_resource_record[0].name
      type = google_certificate_manager_dns_authorization.preview.dns_resource_record[0].type
      data = google_certificate_manager_dns_authorization.preview.dns_resource_record[0].data
    }
  }
}

output "preview_url_pattern" {
  description = "Stable public hostname pattern backed by matching Cloud Run traffic tags."
  value       = "https://pr-N.${var.preview_domain}"
}

output "load_balancer_ip" {
  description = "Reserved global IPv4 address for the HTTPS preview frontend."
  value       = google_compute_global_address.preview.address
}
