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

variable "broker_authority_evidence" {
  description = "Evidence that the consumer projects sit under an organization and that every exact IAM Deny permission and exception has been canaried: the organization ID and the run ID of the successful Deny canary. Null keeps the broker without any authority over consumer accounts, so the deployment stays inert until its prerequisites pass."
  type = object({
    deny_canary_run_id = string
    organization_id    = string
  })
  default = null

  validation {
    condition = var.broker_authority_evidence == null || (
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.organization_id)) &&
      can(regex("^[1-9][0-9]*$", var.broker_authority_evidence.deny_canary_run_id))
    )
    error_message = "broker_authority_evidence must carry a numeric organization_id and a numeric deny_canary_run_id, never fabricated placeholders."
  }
}
