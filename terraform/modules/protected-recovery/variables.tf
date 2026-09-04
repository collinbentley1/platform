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
# not a switch: every field is verified against this deployment. The image and
# platform revision must be this plan's own inputs, the Deny canary must have
# succeeded at that same revision and cover at least the module's required
# permissions with the broker excepted, the organization must be the live
# parent of every consumer project (data.google_project.consumer), and every
# target unique ID must be recorded (google_project_iam_custom_role.actuator).
# Null keeps the module without any authority over consumer accounts, which
# is the only state offline inputs can reach: no organization exists, no Deny
# canary has run, and the committed target identities are null. The run's
# success, head SHA, and artifact digest are verified against the GitHub run
# record by the activation review; nothing here can confirm them offline.
variable "broker_authority_evidence" {
  description = "Reviewed evidence, mechanically bound to this deployment, that the consumer projects sit under the named organization and that every exact IAM Deny permission and exception has been canaried at this platform revision against this broker image. Null keeps the broker without any authority over consumer accounts."
  type = object({
    organization_id = string
    platform_sha    = string
    broker_image    = string
    deny_canary = object({
      run_id          = string
      head_sha        = string
      conclusion      = string
      artifact_sha256 = string
      permissions     = list(string)
      exceptions      = list(string)
    })
  })
  default = null

  validation {
    condition = var.broker_authority_evidence == null || try(
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.organization_id)) &&
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.deny_canary.run_id)) &&
      can(regex("^[0-9a-f]{40}$", var.broker_authority_evidence.deny_canary.head_sha)) &&
      can(regex("^[0-9a-f]{64}$", var.broker_authority_evidence.deny_canary.artifact_sha256)) &&
      var.broker_authority_evidence.deny_canary.conclusion == "success",
      false,
    )
    error_message = "broker_authority_evidence must carry a numeric organization_id, a numeric deny_canary.run_id, a full head_sha, a sha256 artifact digest, and conclusion \"success\"; never fabricated placeholders."
  }

  validation {
    condition = var.broker_authority_evidence == null || try(
      var.broker_authority_evidence.platform_sha == var.active_workflow_sha &&
      var.broker_authority_evidence.deny_canary.head_sha == var.active_workflow_sha &&
      var.broker_authority_evidence.broker_image == var.broker_image,
      false,
    )
    error_message = "broker_authority_evidence must be bound to this deployment: platform_sha and deny_canary.head_sha must equal active_workflow_sha, and broker_image must equal the digest-pinned broker_image being deployed."
  }

  validation {
    condition = var.broker_authority_evidence == null || try(
      length(setsubtract(local.required_deny_coverage, toset(var.broker_authority_evidence.deny_canary.permissions))) == 0 &&
      contains(var.broker_authority_evidence.deny_canary.exceptions, local.broker_principal),
      false,
    )
    error_message = "broker_authority_evidence.deny_canary must cover every permission in the module's required Deny coverage and except exactly the broker principal; a canary of a smaller set cannot enable authority."
  }
}
