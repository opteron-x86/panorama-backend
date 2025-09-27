# backend.tf
terraform {
  backend "s3" {
    bucket         = "panorama-terraform-state-538269499906"
    key            = "panorama/terraform.tfstate"
    region         = "us-east-2"
    encrypt        = true
    use_lockfile = true
  }
}