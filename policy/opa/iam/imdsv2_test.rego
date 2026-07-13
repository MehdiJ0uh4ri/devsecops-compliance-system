package iam.imdsv2

import rego.v1

test_allow_imdsv2_enforced if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_instance",
		"address": "aws_instance.web",
		"change": {"after": {"metadata_options": [{"http_tokens": "required", "http_endpoint": "enabled"}]}},
	}]}
}

test_deny_missing_metadata_options if {
	deny["aws_instance \"aws_instance.web\" must define metadata_options with http_tokens=required (IMDSv2)"] with input as {"resource_changes": [{
		"type": "aws_instance",
		"address": "aws_instance.web",
		"change": {"after": {"instance_type": "t3.micro"}},
	}]}
}

test_deny_imdsv1_optional if {
	deny["aws_instance \"aws_instance.web\" must set metadata_options.http_tokens=\"required\" to enforce IMDSv2"] with input as {"resource_changes": [{
		"type": "aws_instance",
		"address": "aws_instance.web",
		"change": {"after": {"metadata_options": [{"http_tokens": "optional"}]}},
	}]}
}

test_deny_launch_template_imdsv1 if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_launch_template",
		"address": "aws_launch_template.workers",
		"change": {"after": {"metadata_options": [{"http_tokens": "optional"}]}},
	}]}
}

test_allow_non_ec2_resource_ignored if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket",
		"address": "aws_s3_bucket.data",
		"change": {"after": {"bucket": "my-bucket"}},
	}]}
}

test_single_resource_shape if {
	deny["aws_instance \"aws_instance.web\" must set metadata_options.http_tokens=\"required\" to enforce IMDSv2"] with input as {
		"type": "aws_instance",
		"address": "aws_instance.web",
		"values": {"metadata_options": {"http_tokens": "optional"}},
	}
}
