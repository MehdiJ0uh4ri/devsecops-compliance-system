terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "eu-west-1"
}

variable "vpc_id" {
  type        = string
  description = "VPC the sample-app instance and its security group are deployed into."
}

variable "trusted_admin_cidr" {
  type        = string
  description = "Narrow CIDR (e.g. office/VPN egress) allowed to reach SSH - never 0.0.0.0/0."
}

# --- Compliant example: enforced by policy/opa/iam/imdsv2.rego ---
resource "aws_instance" "sample_app" {
  ami           = "ami-0c55b159cbfafe1f0" # placeholder AMI id
  instance_type = "t3.micro"

  metadata_options {
    http_tokens                 = "required" # IMDSv2 enforced - see policy/opa/iam/imdsv2.rego
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  vpc_security_group_ids = [aws_security_group.sample_app.id]

  tags = {
    Name = "sample-app"
  }
}

# --- Compliant example: enforced by policy/opa/network/no_open_sg.rego ---
# Only 443 is open to the world (public HTTPS ingress); everything else is
# restricted to a named CIDR.
resource "aws_security_group" "sample_app" {
  name        = "sample-app"
  description = "sample-app ingress - HTTPS public, SSH restricted to trusted CIDR only"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from anywhere (public load-balanced service)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from trusted admin network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.trusted_admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sample-app"
  }
}

output "instance_id" {
  value = aws_instance.sample_app.id
}
