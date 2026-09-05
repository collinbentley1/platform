output "broker_url" {
  description = "Deterministic Cloud Run URL of the broker; also the ID-token audience every invoker and the reconciler must present."
  value       = local.broker_url
}

output "broker_service_account_email" {
  description = "The only identity that transacts in the ledger, projects evidence, inventories credential paths, and compare-and-sets consumer service-account policies."
  value       = google_service_account.broker.email
}

output "reconciler_service_account_email" {
  description = "Low-authority Cloud Scheduler identity that may only reconcile recorded operations."
  value       = google_service_account.reconciler.email
}

output "invoker_service_account_emails" {
  description = "Purpose-level invoker per consumer and effect direction, keyed <consumer>/<intent>; each holds only run.invoker on the broker."
  value       = { for invoker, account in google_service_account.invoker : invoker => account.email }
}

output "workload_identity_provider" {
  description = "Full Workload Identity Provider resource name the invoke workflow exchanges through."
  value       = "${local.workload_identity_pool}/providers/${google_iam_workload_identity_pool_provider.platform.workload_identity_pool_provider_id}"
}

output "member_workload_identity_provider" {
  description = "Full Workload Identity Provider resource name the consumers' canonical jobs exchange through to deliver their credentials."
  value       = "${local.workload_identity_pool}/providers/${google_iam_workload_identity_pool_provider.members.workload_identity_pool_provider_id}"
}

output "member_service_account_emails" {
  description = "Member-delivery identity per consumer; each holds only run.invoker on the broker and is reachable only by that consumer's canonical jobs."
  value       = { for consumer, account in google_service_account.member : consumer => account.email }
}

output "deny_canary_service_account_email" {
  description = "The Deny canary identity, bound to the canary job's exact tuple and granted nothing by this module."
  value       = google_service_account.deny_canary.email
}

output "activation_blocked" {
  description = "Mutations this module's own apply makes that the required Deny matrix would deny their principal; empty when the activation sequence is permitted."
  value       = local.activation_blocked
}

output "evidence_bucket_name" {
  description = "Immutable evidence bucket that projects committed ledger state."
  value       = google_storage_bucket.evidence.name
}

output "ledger_database" {
  description = "Exact Firestore database that orders every accepted operation."
  value       = google_firestore_database.ledger.name
}

output "required_deny_matrix" {
  description = "The exact IAM Deny matrix the live Deny state must carry and the Deny canary must have proven before broker_authority_evidence can enable authority: per attachment point and permission, the denied principal set and the exact exception set, keyed <attachment>|<permission>. The canary exercises the live policies and attests the result; the module verifies the attested result and the live state against this same definition."
  value       = local.required_deny_matrix
}

output "deny_canary_contract" {
  description = "What the Deny canary must produce for its result to be admissible: the workflow whose run is named, the artifact it uploads, and the attestation predicate type and schema the module decodes."
  value = {
    artifact       = local.deny_canary_artifact
    predicate_type = local.deny_canary_predicate_type
    schema         = local.deny_canary_schema
    workflow       = local.deny_canary_workflow
  }
}
