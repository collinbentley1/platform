variable "project_id" {
  description = "Google Cloud project ID of the protected-recovery broker. The security project does not exist yet; protected-recovery/authority.json records its coordinates once it does."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project ID."
  }
}

variable "broker_image" {
  description = "Broker container image pinned by sha256 digest."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$", var.broker_image))
    error_message = "broker_image must be an image reference pinned by a full sha256 digest."
  }
}

variable "max_instances" {
  description = "Conservative Cloud Run instance ceiling. An availability control only: correctness holds with any number of instances, including zero."
  type        = number
  default     = 2

  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 3 && floor(var.max_instances) == var.max_instances
    error_message = "max_instances must be a whole number between 1 and 3."
  }
}

variable "active_workflow_sha" {
  description = "Exact reviewed platform commit whose protected-recovery-invoke workflow exchanges GitHub OIDC tokens for the purpose-level invokers."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.active_workflow_sha))
    error_message = "active_workflow_sha must be one full lowercase commit SHA."
  }
}

variable "transition_workflow_sha" {
  description = "Optional immediately previous reviewed platform commit that may keep exchanging while the invoke workflow is repinned. Null at steady state."
  type        = string
  default     = null

  validation {
    condition     = var.transition_workflow_sha == null || can(regex("^[0-9a-f]{40}$", var.transition_workflow_sha))
    error_message = "transition_workflow_sha must be null or one full lowercase commit SHA."
  }

  validation {
    condition     = var.transition_workflow_sha != var.active_workflow_sha
    error_message = "transition_workflow_sha must differ from active_workflow_sha."
  }
}

# Evidence that enables the broker's authority over consumer accounts. It is
# not a switch and it carries no claim: it names the reviewed organization and
# one GitHub Actions run of the Deny canary workflow, its uploaded artifact,
# and that artifact's digest. Everything the gate decides on is then read from
# authenticated, immutable records rather than from these inputs: the run's
# conclusion, attempt, head commit, workflow path, event, and repository from
# the GitHub run record; the artifact's digest and run from the GitHub
# artifact record; the canary's organization, broker image, every Deny policy
# attachment point, denied principal set, exact exception set, denied
# permission, per-permission DENIED observation, and unsupported permissions
# from the artifact's attested predicate served by GitHub's attestation store
# (see main.tf, locals evidence_checks and required_deny_matrix). Every check
# must pass, the organization must be the live parent of every consumer
# project, and every target's permanent unique ID must be recorded and resolve
# live to its current email, or the plan fails; nothing supplied here can
# widen a grant.
variable "broker_authority_evidence" {
  description = "The reviewed organization and the GitHub run, artifact ID, and artifact sha256 digest of the successful Deny canary at this platform revision against this broker image. Null keeps the broker without any authority over consumer accounts; every other field is verified against GitHub's run, artifact, and attestation records and the live consumer projects."
  type = object({
    organization_id = string
    deny_canary = object({
      run_id          = string
      artifact_id     = string
      artifact_sha256 = string
    })
  })
  default = null

  validation {
    condition = var.broker_authority_evidence == null || try(
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.organization_id)) &&
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.deny_canary.run_id)) &&
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.deny_canary.artifact_id)) &&
      can(regex("^[0-9a-f]{64}$", var.broker_authority_evidence.deny_canary.artifact_sha256)),
      false,
    )
    error_message = "broker_authority_evidence must carry a numeric organization_id, a numeric deny_canary.run_id, a numeric deny_canary.artifact_id, and a sha256 artifact digest; never fabricated placeholders."
  }
}
