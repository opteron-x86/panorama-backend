# resources.tf
# Missing resources for rule processing pipeline

# S3 bucket for staging rulesets
resource "aws_s3_bucket" "staging" {
  bucket = "panorama-staging-${data.aws_caller_identity.current.account_id}"
  tags   = var.common_tags
}

resource "aws_s3_bucket_versioning" "staging" {
  bucket = aws_s3_bucket.staging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "staging" {
  bucket = aws_s3_bucket.staging.id

  rule {
    id     = "cleanup-old-rulesets"
    status = "Enabled"
    
    filter {
      prefix = "rulesets/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }
  }

  rule {
    id     = "cleanup-parsed-rules"
    status = "Enabled"
    
    filter {
      prefix = "parsed/"
    }

    expiration {
      days = 7
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "staging" {
  bucket = aws_s3_bucket.staging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name            = "panorama-rules-alerts"
  display_name    = "Panorama Rules Processing Alerts"
  delivery_policy = jsonencode({
    "http" : {
      "defaultHealthyRetryPolicy" : {
        "minDelayTarget" : 20,
        "maxDelayTarget" : 20,
        "numRetries" : 3,
        "numMaxDelayRetries" : 0,
        "numNoDelayRetries" : 0,
        "numMinDelayRetries" : 0,
        "backoffFunction" : "linear"
      },
      "disableSubscriptionOverrides" : false
    }
  })
  tags = var.common_tags
}

resource "aws_sns_topic_subscription" "alerts_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Data sources for current account
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}


# EventBridge schedule for automated downloads
resource "aws_cloudwatch_event_rule" "sigma_download_schedule" {
  name                = "sigma-download-schedule"
  description         = "Schedule for automatic Sigma rule downloads"
  schedule_expression = "rate(6 hours)"
  state               = var.enable_auto_download ? "ENABLED" : "DISABLED"
  tags                = var.common_tags
}

resource "aws_cloudwatch_event_target" "sigma_download" {
  rule      = aws_cloudwatch_event_rule.sigma_download_schedule.name
  target_id = "sigma-downloader"
  arn = aws_lambda_function.pano_sigma_downloader.arn
  
  input = jsonencode({
    source = "sigma"
  })
}

resource "aws_lambda_permission" "eventbridge_sigma_downloader" {
  statement_id  = "AllowExecutionFromEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_sigma_downloader.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sigma_download_schedule.arn
}

# IAM permissions for Lambda to access S3
resource "aws_iam_policy" "lambda_s3_access" {
  name        = "panorama-lambda-s3-access"
  description = "Allow Lambda functions to access staging bucket"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.staging.arn,
          "${aws_s3_bucket.staging.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_s3_access" {
  role       = "panorama-lambda-exec-role"
  policy_arn = aws_iam_policy.lambda_s3_access.arn
}

# IAM permissions for Lambda to publish to EventBridge
resource "aws_iam_policy" "lambda_eventbridge_access" {
  name        = "panorama-lambda-eventbridge-access"
  description = "Allow Lambda functions to publish events"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = [
          "arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/${aws_cloudwatch_event_bus.rules_processing.name}",
          "arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_eventbridge_access" {
  role       = "panorama-lambda-exec-role"
  policy_arn = aws_iam_policy.lambda_eventbridge_access.arn
}