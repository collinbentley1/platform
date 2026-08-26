locals {
  # These are the only legacy mappings that have not yet been adopted into the
  # protected exposure state. The import identities are fixed in trusted
  # platform code: neither a workflow caller nor a consumer repository can
  # choose a Terraform address or a remote object ID.
  runsetta_domain_mapping_imports = var.repository_id == "711292980" ? {
    "runsetta.com" = "locations/us-east4/namespaces/runsetta/domainmappings/runsetta.com"
    "www.runsetta.com" = "locations/us-east4/namespaces/runsetta/domainmappings/www.runsetta.com"
  } : {}
}

import {
  for_each = local.runsetta_domain_mapping_imports

  to = module.domains.google_cloud_run_domain_mapping.site[each.key]
  id = each.value
}
