package containers.no_root

# Deny Kubernetes Pod/Deployment/StatefulSet/DaemonSet specs that can run as root.
# Evaluated against Kubernetes manifests (YAML->JSON) or Terraform plan JSON via conftest.
#
# Rules enforced:
#   1. securityContext.runAsNonRoot must be true (pod-level or every container-level)
#   2. securityContext.allowPrivilegeEscalation must be false
#   3. securityContext.privileged must not be true
#   4. runAsUser must not be 0 when explicitly set

import rego.v1

pod_kinds := {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}

pod_spec(input_doc) := input_doc.spec.template.spec if {
	input_doc.kind in pod_kinds
	input_doc.kind != "Pod"
}

pod_spec(input_doc) := input_doc.spec if {
	input_doc.kind == "Pod"
}

all_containers(spec) := array.concat(
	object.get(spec, "containers", []),
	object.get(spec, "initContainers", []),
)

# 1. privileged containers
deny contains msg if {
	spec := pod_spec(input)
	some c in all_containers(spec)
	c.securityContext.privileged == true
	msg := sprintf("container %q must not run privileged", [c.name])
}

# 2. privilege escalation
deny contains msg if {
	spec := pod_spec(input)
	some c in all_containers(spec)
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation=false", [c.name])
}

# 3. explicit root UID
deny contains msg if {
	spec := pod_spec(input)
	some c in all_containers(spec)
	c.securityContext.runAsUser == 0
	msg := sprintf("container %q must not set runAsUser: 0 (root)", [c.name])
}

# 4. runAsNonRoot must be explicitly true somewhere (pod-level or per-container)
deny contains msg if {
	spec := pod_spec(input)
	not pod_level_non_root(spec)
	some c in all_containers(spec)
	not c.securityContext.runAsNonRoot == true
	msg := sprintf("container %q must set securityContext.runAsNonRoot=true (or set it at pod level)", [c.name])
}

pod_level_non_root(spec) if {
	spec.securityContext.runAsNonRoot == true
}
