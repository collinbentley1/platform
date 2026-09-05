terraform {
  required_version = "~> 1.14.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.34.0"
    }
    # Read-only reads of the GitHub run and artifact records and of the live
    # IAM Deny policies that authenticate the Deny canary evidence; nothing is
    # written.
    http = {
      source  = "hashicorp/http"
      version = "= 3.6.1"
    }
    # The cryptographic verification of the canary's attestation, run on the
    # applying machine (tools/ci/protected-recovery-verify-canary.sh).
    external = {
      source  = "hashicorp/external"
      version = "= 2.3.5"
    }
  }
}
