# cognito.tf
resource "aws_cognito_user_pool" "main" {
  name                     = "User pool - Panorama"
  deletion_protection      = "ACTIVE"
  mfa_configuration        = "OFF"
  
  username_attributes      = ["email", "phone_number"]
  auto_verified_attributes = ["email", "phone_number"]
  
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
    recovery_mechanism {
      name     = "verified_phone_number"
      priority = 2
    }
  }
  
  admin_create_user_config {
    allow_admin_create_user_only = false
  }
  
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }
  
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }
  
  sms_configuration {
    external_id    = "db1044fa-5233-4828-a659-27d89931c35a"
    sns_caller_arn = "arn:aws:iam::538269499906:role/service-role/CognitoIdpSNSServiceRole"
    sns_region     = "us-east-2"
  }
  
  username_configuration {
    case_sensitive = false
  }
  
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
  }
}