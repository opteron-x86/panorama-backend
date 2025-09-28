# variables.tf
# Variables for rule processing pipeline

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "panorama"
    ManagedBy   = "terraform"
  }
}

variable "alert_email" {
  description = "Email address for CloudWatch alerts"
  type        = string
  default     = ""
}

variable "enable_auto_download" {
  description = "Enable automatic rule downloads"
  type        = bool
  default     = true
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}
