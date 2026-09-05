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
# three GitHub Actions runs of the Deny canary workflow -- the control phase,
# the deny phase, and the cleanup that followed them -- each with its uploaded
# artifact and that artifact's two digests: the sha256 of the raw predicate
# file the attestation signs, and the sha256 of the archive GitHub records
# for the artifact. Everything the gate decides on is then read from
# authenticated, immutable records rather than from these inputs: each run's
# conclusion, attempt, head commit, workflow path, event, repository, and
# timing from the GitHub run record; each artifact's digest and run from the
# GitHub artifact record and from the downloaded bytes; the canary's phase,
# organization, broker image, the allow policies it recorded, every Deny
# policy attachment point, denied principal set, exact exception set, denied
# permission, per-permission ALLOWED (control) and DENIED (deny) observation
# with its request digest, pre-state, required permissions, operation, and
# IAM denial, the cleanup's leftovers, and unexercised permissions from each
# artifact's attested predicate served by GitHub's attestation store (see
# main.tf, locals evidence_checks and matrices). Every check must pass, the
# organization must be the live parent of every consumer project and of the
# broker project, every target's permanent unique ID must be recorded and
# resolve live to its current email, and the canary's temporary Allows must
# be gone from every attachment point live, or the apply fails; nothing
# supplied here can widen a grant.
variable "broker_authority_evidence" {
  description = "The reviewed organization and, for the control phase, the deny phase, and the cleanup phase of the Deny canary at this platform revision against this broker image, the GitHub run, artifact ID, raw artifact sha256 digest, and archive sha256 digest. Null keeps the broker without any authority over consumer accounts; every other field is verified against GitHub's run, artifact, and attestation records and the live Deny and allow state."
  type = object({
    organization_id = string
    deny_control = object({
      run_id          = string
      artifact_id     = string
      artifact_sha256 = string
      archive_sha256  = string
    })
    deny_canary = object({
      run_id          = string
      artifact_id     = string
      artifact_sha256 = string
      archive_sha256  = string
    })
    deny_cleanup = object({
      run_id          = string
      artifact_id     = string
      artifact_sha256 = string
      archive_sha256  = string
    })
  })
  default = null

  validation {
    condition = var.broker_authority_evidence == null || try(
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.organization_id)) &&
      alltrue([for phase in [var.broker_authority_evidence.deny_control, var.broker_authority_evidence.deny_canary, var.broker_authority_evidence.deny_cleanup] :
        can(regex("^[1-9][0-9]*$", phase.run_id)) &&
        can(regex("^[1-9][0-9]*$", phase.artifact_id)) &&
        can(regex("^[0-9a-f]{64}$", phase.artifact_sha256)) &&
        can(regex("^[0-9a-f]{64}$", phase.archive_sha256)) &&
        phase.artifact_sha256 != phase.archive_sha256
      ]) &&
      length(distinct([var.broker_authority_evidence.deny_control.run_id, var.broker_authority_evidence.deny_canary.run_id, var.broker_authority_evidence.deny_cleanup.run_id])) == 3,
      false,
    )
    error_message = "broker_authority_evidence must carry a numeric organization_id and, for each of the three canary phases, a numeric run_id distinct from the other phases', a numeric artifact_id, a sha256 raw artifact digest, and a distinct sha256 archive digest; never fabricated placeholders."
  }
}
