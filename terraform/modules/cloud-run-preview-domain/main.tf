locals {
  wildcard_domain = "*.${var.preview_domain}"
}

resource "google_compute_global_address" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-address"
  address_type    = "EXTERNAL"
  ip_version      = "IPV4"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_region_network_endpoint_group" "preview" {
  project               = var.project_id
  name                  = "${var.resource_name_prefix}-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"
  deletion_policy       = "PREVENT"

  cloud_run {
    # The service is fixed in trusted platform code. Only the traffic tag is
    # extracted from the custom hostname, so this NEG cannot route to a
    # production service or a sibling application.
    service  = var.preview_service_name
    url_mask = "<tag>.${var.preview_domain}"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_backend_service" "preview" {
  project               = var.project_id
  name                  = "${var.resource_name_prefix}-backend"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTP"
  timeout_sec           = 30
  deletion_policy       = "PREVENT"

  backend {
    group = google_compute_region_network_endpoint_group.preview.id
  }

  log_config {
    enable      = true
    sample_rate = 1
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_url_map" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-url-map"
  default_service = google_compute_backend_service.preview.id
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_ssl_policy" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-tls"
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_certificate_manager_dns_authorization" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-dns-auth"
  location        = "global"
  domain          = var.preview_domain
  type            = "PER_PROJECT_RECORD"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_certificate_manager_certificate" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-certificate"
  location        = "global"
  deletion_policy = "PREVENT"

  managed {
    domains            = [local.wildcard_domain]
    dns_authorizations = [google_certificate_manager_dns_authorization.preview.id]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_certificate_manager_certificate_map" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-certificate-map"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_certificate_manager_certificate_map_entry" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-wildcard"
  map             = google_certificate_manager_certificate_map.preview.name
  certificates    = [google_certificate_manager_certificate.preview.id]
  hostname        = local.wildcard_domain
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_target_https_proxy" "preview" {
  project         = var.project_id
  name            = "${var.resource_name_prefix}-https-proxy"
  url_map         = google_compute_url_map.preview.id
  certificate_map = "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.preview.id}"
  ssl_policy      = google_compute_ssl_policy.preview.id
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_certificate_manager_certificate_map_entry.preview]
}

resource "google_compute_global_forwarding_rule" "preview_https" {
  project               = var.project_id
  name                  = "${var.resource_name_prefix}-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.preview.address
  ip_protocol           = "TCP"
  port_range            = "443"
  target                = google_compute_target_https_proxy.preview.id
  deletion_policy       = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}
