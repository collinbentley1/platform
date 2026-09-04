output "broker_url" {
  description = "Deterministic Cloud Run URL of the broker; also the ID-token audience every invoker and the reconciler must present."
  value       = local.broker_url
}

output "broker_service_account_email" {
  description = "The only identity that transacts in the ledger, projects evidence, and compare-and-sets consumer service-account policies."
  value       = google_service_account.broker.email
}

output "reconciler_service_account_email" {
  description = "Low-authority Cloud Scheduler identity that may only reconcile recorded operations."
  value       = google_service_account.reconciler.email
}

output "invoker_service_account_emails" {
  description = "Purpose-level invoker per consumer; each holds only run.invoker on the broker."
  value       = { for consumer, account in google_service_account.invoker : consumer => account.email }
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
