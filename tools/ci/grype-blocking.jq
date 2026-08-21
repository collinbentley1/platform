[
  .matches[]
  | select(
      .vulnerability.severity == "Critical" or
      .vulnerability.severity == "High"
    )
  | {
      package: .artifact.name,
      installed: .artifact.version,
      vulnerability: .vulnerability.id,
      severity: .vulnerability.severity,
      fixState: .vulnerability.fix.state,
      fixedIn: .vulnerability.fix.versions
    }
]
