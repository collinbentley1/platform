locals {
  labels = merge(
    {
      app        = var.app
      managed-by = "terraform"
    },
    var.labels,
  )

  firestore_database = var.firestore_database == null ? [] : [var.firestore_database]
  firestore_env = var.firestore_database == null ? {} : merge(
    {
      FIRESTORE_DATABASE_ID = var.firestore_database.name
      FIRESTORE_PROJECT_ID  = var.project_id
    },
    var.firestore_database.runtime_collection_env_name == null ? {} : {
      (var.firestore_database.runtime_collection_env_name) = var.firestore_database.runtime_collection_env_value
    },
  )
}

resource "google_artifact_registry_repository" "site" {
  #checkov:skip=CKV_GCP_84:Google-managed encryption is sufficient for public application container images.
  project       = var.project_id
  location      = var.region
  repository_id = var.artifact_registry_repository_id
  description   = var.artifact_registry_description
  format        = "DOCKER"

  docker_config {
    immutable_tags = true
  }

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "delete-pr-images-after-30-days"
    action = "DELETE"

    condition {
      older_than   = "2592000s"
      tag_prefixes = ["pr-"]
      tag_state    = "TAGGED"
    }
  }

  cleanup_policies {
    id     = "keep-recent-images"
    action = "KEEP"

    most_recent_versions {
      keep_count = 30
    }
  }

  labels = local.labels
}

resource "google_artifact_registry_repository_iam_member" "prod_deploy_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.site.location
  repository = google_artifact_registry_repository.site.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${var.prod_deploy_service_account_email}"
}

resource "google_artifact_registry_repository_iam_member" "preview_deploy_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.site.location
  repository = google_artifact_registry_repository.site.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${var.preview_deploy_service_account_email}"
}

resource "google_artifact_registry_repository_iam_member" "runtime_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.site.location
  repository = google_artifact_registry_repository.site.repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.runtime_service_account_email}"
}

resource "google_secret_manager_secret" "runtime" {
  #checkov:skip=CKV_GCP_82:Runtime secret rotation is application-specific.
  for_each = var.runtime_secret_ids

  project   = var.project_id
  secret_id = each.value

  replication {
    auto {}
  }

  labels = local.labels
}

resource "google_secret_manager_secret_iam_member" "runtime_accessor" {
  for_each = google_secret_manager_secret.runtime

  project   = var.project_id
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.runtime_service_account_email}"
}

resource "google_firestore_database" "firestore" {
  count = length(local.firestore_database)

  project                           = var.project_id
  name                              = local.firestore_database[0].name
  location_id                       = local.firestore_database[0].location_id
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "OPTIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = local.firestore_database[0].point_in_time_recovery_enablement
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
}

resource "google_project_iam_member" "runtime_firestore_user" {
  count = var.firestore_database == null ? 0 : 1

  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${var.runtime_service_account_email}"
}

resource "google_cloud_run_v2_service" "site" {
  project              = var.project_id
  name                 = var.service_name
  location             = var.region
  client               = "terraform"
  deletion_protection  = true
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = true
  labels               = local.labels

  template {
    service_account                  = var.runtime_service_account_email
    timeout                          = "300s"
    max_instance_request_concurrency = 80

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      name  = "site"
      image = var.bootstrap_image

      ports {
        name           = "http1"
        container_port = 8080
      }

      dynamic "env" {
        for_each = merge(var.container_env, local.firestore_env)

        content {
          name  = env.key
          value = env.value
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }

        cpu_idle          = true
        startup_cpu_boost = true
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  lifecycle {
    ignore_changes = [
      client,
      client_version,
      labels,
      template[0].labels,
      template[0].containers[0].env,
      template[0].containers[0].image,
    ]
  }

  depends_on = [
    google_artifact_registry_repository.site,
    google_artifact_registry_repository_iam_member.runtime_reader,
    google_project_iam_member.runtime_firestore_user,
    google_secret_manager_secret_iam_member.runtime_accessor,
  ]
}

resource "google_cloud_run_domain_mapping" "site" {
  for_each = var.custom_domains
  provider = google.no_attribution

  project  = var.project_id
  location = var.region
  name     = each.value

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.site.name
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
