terraform {
  required_version = "~> 1.14.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.34.0"
    }
    # The cryptographic verification of the canary's attestations and the
    # credential-free reads of the live IAM Deny policies, both run on the
    # applying machine (tools/ci/protected-recovery-verify-canary.sh and
    # tools/ci/protected-recovery-deny-state.sh): no request credential ever
    # enters the configuration or the state.
    external = {
      source  = "hashicorp/external"
      version = "= 2.3.5"
    }
  }
}
