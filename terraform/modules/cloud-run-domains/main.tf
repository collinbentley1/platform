resource "google_cloud_run_domain_mapping" "site" {
  for_each = var.domains

  project  = var.project_id
  location = var.region
  name     = each.value

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = var.service_name
  }

  lifecycle {
    prevent_destroy = true
    ignore_changes = [
      metadata[0].annotations,
      metadata[0].labels,
      spec[0].certificate_mode,
      spec[0].force_override,
    ]
  }
}
