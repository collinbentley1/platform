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

  preview_repository_id = "${var.artifact_registry_repository_id}-preview"
  preview_service_name  = "${var.service_name}-preview"
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

# Artifact Registry has no predefined upload-only Docker role. Writer is bound
# to this one repository (never the project); it can upload/read, create or
# update tags, and delete attachments, but cannot delete repository images,
# tags, or versions. Do not replace it with a guessed custom role until crane
# copy + digest is exercised through the protected pipeline against every
# required OCI request.
resource "google_artifact_registry_repository_iam_member" "prod_publisher_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.site.location
  repository = google_artifact_registry_repository.site.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${var.prod_publisher_service_account_email}"
}

resource "google_artifact_registry_repository_iam_member" "preview_publisher_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.preview.location
  repository = google_artifact_registry_repository.preview.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${var.preview_publisher_service_account_email}"
}

# Cloud Run requires the deployer itself to have downloadArtifacts on the image
# repository. The predefined Reader role is the documented deployment contract;
# repository scope contains its metadata and download breadth and grants no
# upload or delete permission.
resource "google_artifact_registry_repository_iam_member" "prod_deploy_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.site.location
  repository = google_artifact_registry_repository.site.repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.prod_deploy_service_account_email}"
}

resource "google_artifact_registry_repository_iam_member" "preview_deploy_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.preview.location
  repository = google_artifact_registry_repository.preview.repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.preview_deploy_service_account_email}"
}

moved {
  from = google_artifact_registry_repository_iam_member.prod_deploy_writer
  to   = google_artifact_registry_repository_iam_member.prod_publisher_writer
}

moved {
  from = google_artifact_registry_repository_iam_member.preview_deploy_writer
  to   = google_artifact_registry_repository_iam_member.preview_publisher_writer
}

resource "google_artifact_registry_repository" "preview" {
  #checkov:skip=CKV_GCP_84:Google-managed encryption is sufficient for public application preview images.
  project       = var.project_id
  location      = var.region
  repository_id = local.preview_repository_id
  description   = "Ephemeral pull request images for ${var.app}."
  format        = "DOCKER"

  docker_config {
    # Preview tags contain PR, commit, run, and attempt. Keeping them mutable lets
    # Artifact Registry's delete policy actually reclaim tagged preview images.
    immutable_tags = false
  }

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "delete-preview-images-after-30-days"
    action = "DELETE"

    condition {
      older_than = "2592000s"
      tag_state  = "ANY"
    }
  }

  labels = merge(local.labels, { environment = "preview" })
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
  for_each = var.runtime_secret_accessor_ids

  project   = var.project_id
  secret_id = google_secret_manager_secret.runtime[each.value].secret_id
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

removed {
  from = google_project_iam_member.runtime_firestore_user

  lifecycle {
    destroy = false
  }
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
    service_account                  = var.bootstrap_runtime_service_account_email
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
      template[0].service_account,
      template[0].containers[0].env,
      template[0].containers[0].image,
    ]
  }

  depends_on = [
    google_artifact_registry_repository.site,
    google_secret_manager_secret_iam_member.runtime_accessor,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "prod_deploy" {
  project  = var.project_id
  location = google_cloud_run_v2_service.site.location
  name     = google_cloud_run_v2_service.site.name
  role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"
  member   = "serviceAccount:${var.prod_deploy_service_account_email}"
}

resource "google_cloud_run_v2_service" "preview" {
  project              = var.project_id
  name                 = local.preview_service_name
  location             = var.region
  client               = "terraform"
  deletion_protection  = true
  ingress              = var.preview_ingress
  invoker_iam_disabled = true
  labels               = merge(local.labels, { environment = "preview" })

  template {
    service_account                  = var.preview_runtime_service_account_email
    timeout                          = "300s"
    max_instance_request_concurrency = 80

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }

    containers {
      name  = "site"
      image = var.bootstrap_image

      ports {
        name           = "http1"
        container_port = 8080
      }

      env {
        name  = "PLATFORM_DEPLOY_ENVIRONMENT"
        value = "preview"
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
      # deploy-preview owns deterministic revision names. Land preview template
      # changes through that workflow first to avoid immutable-name conflicts.
      template[0].revision,
      template[0].containers[0].env,
      template[0].containers[0].image,
      traffic,
    ]
  }

  depends_on = [
    google_artifact_registry_repository.preview,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "preview_deploy" {
  project  = var.project_id
  location = google_cloud_run_v2_service.preview.location
  name     = google_cloud_run_v2_service.preview.name
  role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"
  member   = "serviceAccount:${var.preview_deploy_service_account_email}"
}

removed {
  from = google_cloud_run_domain_mapping.site

  lifecycle {
    destroy = false
  }
}
