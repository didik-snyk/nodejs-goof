deny[msg] {
  vulnerability := input.vulnerabilities[_]
  rating := vulnerability.ratings[_]
  rating.source.name == "Snyk"
  rating.score > max_cvss_score
  component := input.components[_]
  bom_ref = vulnerability["bom-ref"]
  component["bom-ref"] == bom_ref

  root = input.metadata.component["bom-ref"]

  dependency := input.dependencies[_]
  dependency.ref == root

  direct := dependency.dependsOn[_]
  direct == bom_ref

  msg := sprintf("%s version %s has a vulnerability with a CVSS score of %s", [component.name, component.version, round(rating.score)])
}

round(n) = f {
  f := sprintf("%.2f", [n])
  contains(f, ".") # Ensure that it was a float
}

round(n) = f {
  not contains(sprintf("%.2f", [n]), ".") # Test if it wasn't a float
  f := sprintf("%v.00", [n]) # Fudge the decimals for integer values
}
