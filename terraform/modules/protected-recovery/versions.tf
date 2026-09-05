terraform {
  required_version = "~> 1.14.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.34.0"
    }
    # Read-only reads of the GitHub run, artifact, and attestation records
    # that authenticate the Deny canary evidence; nothing is written.
    http = {
      source  = "hashicorp/http"
      version = "= 3.6.1"
    }
  }
}
