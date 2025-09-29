# variables.tf

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Environment = "dev"
    Project     = "panorama"
    ManagedBy   = "terraform"
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-2"
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

variable "github_token" {
  description = "GitHub personal access token for API rate limits"
  type        = string
  default     = ""
  sensitive   = true
}

variable "nvd_api_key" {
  description = "NVD API key for CVE enrichment"
  type        = string
  default     = ""
  sensitive   = true
}

variable "cors_origin" {
  description = "CORS origin for API Gateway"
  type        = string
  default     = "*"
}