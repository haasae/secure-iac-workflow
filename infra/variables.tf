variable "aws_region" {
  description = "AWS region for the S3 bucket"
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name"
  type        = string
}

variable "project_name" {
  description = "Name prefix for the IAM and network resources"
  type        = string
  default     = "secure-iac-workflow"
}

variable "vpc_cidr" {
  description = "IPv4 range of the VPC. Ingress to the app is limited to this range"
  type        = string
  default     = "10.0.0.0/16"
}
