output "broker_url" {
  description = "Deterministic Cloud Run URL of the broker; also the ID-token audience every invoker and the reconciler must present."
  value       = local.broker_url
}

output "broker_service_account_email" {
  description = "The only identity that transacts in the ledger, projects evidence, inventories credential paths and the live Deny state, and compare-and-sets consumer service-account policies."
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
  description = "Mutations this module's own apply makes that the bootstrap form of the required Deny matrix would deny their principal; empty when the activation sequence is permitted."
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
  description = "The steady form of the exact IAM Deny matrix: per attachment point (the broker project, the organization, every consumer project) and permission, the denied principal set and the exact exception set, keyed <attachment>|<permission>. The only form under which the broker exercises authority; the canary exercises the live policies and attests the result, and the module verifies the attested result and the live state against this same definition."
  value       = local.required_deny_matrix
}

output "bootstrap_deny_matrix" {
  description = "The bootstrap form: the steady matrix with the authority's bootstrap principal excepted on exactly the rows this module's own apply mutates. The root installs it for the activation apply and retires the exception afterwards; the broker refuses every quarantine until it reads the steady form live."
  value       = local.matrices.bootstrap
}

output "maintenance_deny_matrix" {
  description = "The maintenance form: the steady matrix with the authority's maintenance principals excepted on the consumer IAM, federation, lifecycle, API, role, and organization-policy rows. The root installs it only under a maintenance ticket the broker has opened (POST /v1/maintenance), which no quarantine can overlap; this module refuses to plan under it."
  value       = local.matrices.maintenance
}

output "deployment_deny_matrix" {
  description = "The deployment form for every consumer at once: the steady matrix with each consumer's two deploy identities excepted from exactly run.services.create|update and actAs at that consumer's project. A consumer's ordinary state, under which its canonical deploy jobs run and the broker admits no quarantine of it."
  value       = local.matrices.deployment
}

output "deny_canary_contract" {
  description = "What the Deny canary must produce for its result to be admissible: the workflow whose runs are named, the three attested phases, the artifact each phase uploads, the attestation predicate types and schemas the module decodes, the canary principal every observation must name, the consumer attachment rows that may rest on a SERVICE_DISABLED answer beside a live read of the API's state, and the rows whose pre-state the deny phase may record as unknown."
  value = {
    artifact                  = local.deny_canary_artifact
    canary                    = local.canary_principal
    cleanup_artifact          = local.deny_cleanup_artifact
    cleanup_predicate_type    = local.deny_cleanup_predicate_type
    cleanup_schema            = local.deny_cleanup_schema
    phases                    = sort(keys(local.canary_phases))
    predicate_type            = local.deny_canary_predicate_type
    schema                    = local.deny_canary_schema
    unobservable_prestate     = local.unobservable_prestate
    unserviceable_permissions = local.unserviceable_permissions
    workflow                  = local.deny_canary_workflow
  }
}

output "unserviceable_rows" {
  description = "Required consumer attachment rows whose evidence is the identical request answering SERVICE_DISABLED in both canary phases beside a live read proving the API disabled, rather than a proven denial; empty when every row is proven denied, and empty without evidence."
  value       = local.authority_enabled ? local.unserviceable_rows : []
}

output "co_denied_rows" {
  description = "Required rows whose deny-phase request needs a second permission the matrix denies at the same attachment point (Cloud Run writes need actAs beside their own permission; the implicit-delegation chain needs the delegate's getAccessToken), so each is proven by the denial naming its own permission beside an isolated proof of the other; empty without evidence."
  value       = local.authority_enabled ? local.co_denied_rows : []
}
