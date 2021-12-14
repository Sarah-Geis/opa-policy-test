package fairwinds

blockedNamespace(elem) {
  ns := elem.parameters.blocklist[_]
  elem.metadata.namespace == ns
  }
  
violation[actionItem] {
 container := input.spec.template.spec.containers[_]
 satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
 not any(satisfied)
 msg := sprintf("container <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
   actionItem := {
    "title": "Allowed Container Image registries",
    "description": "Container image does not come from approved registry",
    "remediation": "Can only use images from x",
    "category": "Reliability",
    "severity": 0.7,
  }
}

 violation[actionItem] {
  container := input.spec.template.spec.initContainers[_]
  satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
  not any(satisfied)
  msg := sprintf("container <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
  actionItem := {
    "title": "Allowed Container Image registries",
    "description": "Container image does not come from approved registry",
    "remediation": "Can only use images from x",
    "category": "Reliability",
    "severity": 0.7,
  }
}
