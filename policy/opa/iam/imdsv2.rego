package iam.imdsv2

# Deny EC2 instances / launch templates that do not enforce IMDSv2.
# Works against `terraform show -json <plan>` (resource_changes[].change.after)
# so it can run in CI as a PR-time policy gate via conftest.

import rego.v1

ec2_types := {"aws_instance", "aws_launch_template", "aws_launch_configuration"}

# normalize: conftest/terraform plan JSON wraps resources in resource_changes;
# support being pointed directly at a single resource `after` block too.
target_resources contains resource if {
	some rc in input.resource_changes
	rc.type in ec2_types
	resource := object.union({"type": rc.type, "address": rc.address}, after(rc))
}

target_resources contains resource if {
	not input.resource_changes
	input.type in ec2_types
	resource := object.union({"type": input.type, "address": object.get(input, "address", input.type)}, {"after": input.values})
}

after(rc) := {"after": rc.change.after} if {
	rc.change.after != null
}

metadata_options(after) := opts if {
	is_array(after.metadata_options)
	count(after.metadata_options) > 0
	opts := after.metadata_options[0]
}

metadata_options(after) := after.metadata_options if {
	is_object(after.metadata_options)
}

deny contains msg if {
	some r in target_resources
	r.type in {"aws_instance", "aws_launch_template"}
	not metadata_options(r.after)
	msg := sprintf("%s %q must define metadata_options with http_tokens=required (IMDSv2)", [r.type, r.address])
}

deny contains msg if {
	some r in target_resources
	r.type in {"aws_instance", "aws_launch_template"}
	opts := metadata_options(r.after)
	opts.http_tokens != "required"
	msg := sprintf("%s %q must set metadata_options.http_tokens=\"required\" to enforce IMDSv2", [r.type, r.address])
}

deny contains msg if {
	some r in target_resources
	r.type in {"aws_instance", "aws_launch_template"}
	opts := metadata_options(r.after)
	opts.http_endpoint == "disabled"
	msg := sprintf("%s %q disables the instance metadata endpoint entirely; enable it with IMDSv2 enforced instead of relying on absence", [r.type, r.address])
}
