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

output "evidence_bucket_name" {
  description = "Immutable evidence bucket that projects committed ledger state."
  value       = google_storage_bucket.evidence.name
}

output "ledger_database" {
  description = "Exact Firestore database that orders every accepted operation."
  value       = google_firestore_database.ledger.name
}

output "required_deny_matrix" {
  description = "The exact IAM Deny matrix the Deny canary must prove before broker_authority_evidence can enable authority: per attachment point and permission, the denied principal set and the exact exception set, keyed <attachment>|<permission>. The canary exercises exactly this and attests the result; the module verifies the attested result against this same definition."
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
