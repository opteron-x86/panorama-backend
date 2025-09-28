# monitoring.tf
# CloudWatch dashboard for rule processing pipeline

resource "aws_cloudwatch_dashboard" "rules_pipeline" {
  dashboard_name = "panorama-rules-pipeline"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", { stat = "Sum", label = "Downloader" }],
            [".", ".", { stat = "Sum", label = "Sigma Parser" }],
            [".", ".", { stat = "Sum", label = "Universal Processor" }]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Lambda Invocations"
          period  = 300
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", { stat = "Average" }],
            [".", ".", { stat = "Maximum" }]
          ]
          view   = "timeSeries"
          region = var.aws_region
          title  = "Processing Duration"
          period = 300
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Errors", { stat = "Sum" }],
            ["AWS/Lambda", "Throttles", { stat = "Sum" }]
          ]
          view   = "timeSeries"
          region = var.aws_region
          title  = "Errors and Throttles"
          period = 300
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Events", "SuccessfulRuleMatches", { stat = "Sum" }],
            [".", "FailedInvocations", { stat = "Sum" }]
          ]
          view   = "timeSeries"
          region = var.aws_region
          title  = "EventBridge Activity"
          period = 300
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", 
             { stat = "Average", label = "DLQ Messages" }]
          ]
          view   = "singleValue"
          region = var.aws_region
          title  = "Dead Letter Queue"
          period = 300
        }
      },
      {
        type = "log"
        properties = {
          query = <<-EOQ
            SOURCE '/aws/lambda/pano-sigma-parser'
            | SOURCE '/aws/lambda/pano-universal-processor'
            | fields @timestamp, @message
            | filter @message like /ERROR/
            | sort @timestamp desc
            | limit 20
          EOQ
          region = var.aws_region
          title  = "Recent Errors"
        }
      }
    ]
  })
}

# Log groups with retention
resource "aws_cloudwatch_log_group" "sigma_parser" {
  name              = "/aws/lambda/pano-sigma-parser"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "universal_processor" {
  name              = "/aws/lambda/pano-universal-processor"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "rule_downloader" {
  name              = "/aws/lambda/pano-rule-downloader"
  retention_in_days = 14
  tags              = var.common_tags
}

# Metric filters for custom metrics
resource "aws_cloudwatch_log_metric_filter" "rules_processed" {
  name           = "rules-processed"
  log_group_name = aws_cloudwatch_log_group.universal_processor.name
  pattern        = "[time, request_id, level = INFO, msg = Successfully*, processed = processed, count, ...]"
  
  metric_transformation {
    name      = "RulesProcessed"
    namespace = "Panorama/Rules"
    value     = "$count"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "processing_errors" {
  name           = "processing-errors"
  log_group_name = aws_cloudwatch_log_group.universal_processor.name
  pattern        = "[time, request_id, level = ERROR, ...]"
  
  metric_transformation {
    name      = "ProcessingErrors"
    namespace = "Panorama/Rules"
    value     = "1"
    unit      = "Count"
  }
}

# Alarms
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "panorama-rules-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "High error rate in rule processing pipeline"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.pano_universal_processor.function_name
  }

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "processing_duration" {
  alarm_name          = "panorama-rules-slow-processing"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "240000"  # 4 minutes in milliseconds
  alarm_description   = "Rule processing taking too long"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.pano_universal_processor.function_name
  }

  tags = var.common_tags
}