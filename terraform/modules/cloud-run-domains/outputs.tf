output "dns_records" {
  description = "DNS records reported by each Cloud Run domain mapping."
  value = {
    for domain, mapping in google_cloud_run_domain_mapping.site : domain => try(mapping.status[0].resource_records, [])
  }
}
