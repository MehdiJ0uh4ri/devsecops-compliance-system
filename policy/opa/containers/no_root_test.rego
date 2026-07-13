package containers.no_root

import rego.v1

test_allow_compliant_pod if {
	count(deny) == 0 with input as {
		"kind": "Pod",
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{
				"name": "app",
				"securityContext": {
					"allowPrivilegeEscalation": false,
					"runAsNonRoot": true,
				},
			}],
		},
	}
}

test_deny_privileged_container if {
	deny["container \"app\" must not run privileged"] with input as {
		"kind": "Pod",
		"spec": {"containers": [{
			"name": "app",
			"securityContext": {"privileged": true, "allowPrivilegeEscalation": false, "runAsNonRoot": true},
		}]},
	}
}

test_deny_root_uid if {
	some msg in deny
	contains(msg, "runAsUser: 0")
		with input as {
			"kind": "Deployment",
			"spec": {"template": {"spec": {"containers": [{
				"name": "app",
				"securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": false},
			}]}}},
		}
}

test_deny_missing_non_root_flag if {
	count(deny) > 0 with input as {
		"kind": "Pod",
		"spec": {"containers": [{
			"name": "app",
			"securityContext": {"allowPrivilegeEscalation": false},
		}]},
	}
}

test_deny_privilege_escalation_allowed if {
	deny["container \"app\" must set securityContext.allowPrivilegeEscalation=false"] with input as {
		"kind": "Pod",
		"spec": {"containers": [{
			"name": "app",
			"securityContext": {"allowPrivilegeEscalation": true, "runAsNonRoot": true},
		}]},
	}
}

test_pod_level_non_root_covers_containers_without_it if {
	count(deny) == 0 with input as {
		"kind": "Pod",
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{"name": "app", "securityContext": {"allowPrivilegeEscalation": false}}],
		},
	}
}
