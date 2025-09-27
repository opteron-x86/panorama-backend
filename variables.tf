variable "environment" {
  type        = string
  default     = "prod"
  description = "Environment name"
}

variable "aws_region" {
  type        = string
  default     = "us-east-2"
  description = "AWS region"
}

variable "common_tags" {
  type = map(string)
  default = {
    ManagedBy   = "terraform"
    Project     = "panorama"
    Environment = "prod"
  }
}