# eventbridge.tf
# EventBridge configuration for rule processing pipeline

resource "aws_cloudwatch_event_bus" "rules_processing" {
  name = "panorama-rules-processing"
  tags = var.common_tags
}

# Rule: Trigger Sigma parser when rules downloaded
resource "aws_cloudwatch_event_rule" "sigma_parser_trigger" {
  name           = "trigger-sigma-parser"
  description    = "Trigger Sigma parser when rules downloaded"
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name

  event_pattern = jsonencode({
    source      = ["rules.downloader"]
    detail-type = ["com.security.rules.downloaded"]
    detail = {
      source = ["sigma"]
    }
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "sigma_parser" {
  rule           = aws_cloudwatch_event_rule.sigma_parser_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name
  target_id      = "sigma-parser"
  arn            = aws_lambda_function.pano_sigma_parser.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }

  dead_letter_config {
    arn = aws_sqs_queue.rules_dlq.arn
  }
}


# Rule: Trigger universal processor when rules parsed
resource "aws_cloudwatch_event_rule" "universal_processor_trigger" {
  name           = "trigger-universal-processor"
  description    = "Trigger universal processor when rules are parsed"
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name

  event_pattern = jsonencode({
    source = [
      "rules.parser.sigma"
    ]
    detail-type = ["com.security.rules.parsed"]
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "universal_processor" {
  rule           = aws_cloudwatch_event_rule.universal_processor_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name
  target_id      = "universal-processor"
  arn            = aws_lambda_function.pano_universal_processor.arn

  retry_policy {
    maximum_event_age_in_seconds = 7200
    maximum_retry_attempts       = 3
  }

  dead_letter_config {
    arn = aws_sqs_queue.rules_dlq.arn
  }
}

# Rule: Handle processing failures
resource "aws_cloudwatch_event_rule" "processing_failures" {
  name           = "handle-processing-failures"
  description    = "Handle rule processing failures"
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name

  event_pattern = jsonencode({
    source = [
      "rules.downloader",
      "rules.parser.sigma",
      "rules.processor"
    ]
    detail-type = ["com.security.rules.failed"]
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "failure_handler" {
  rule           = aws_cloudwatch_event_rule.processing_failures.name
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name
  target_id      = "failure-handler"
  arn            = aws_sqs_queue.rules_dlq.arn
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "rules_dlq" {
  name                       = "panorama-rules-dlq"
  message_retention_seconds  = 1209600  # 14 days
  visibility_timeout_seconds = 300

  tags = var.common_tags
}

resource "aws_sqs_queue" "rules_dlq_alarm" {
  name = "panorama-rules-dlq-alarm"
  tags = var.common_tags
}

# CloudWatch alarm for DLQ
resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "panorama-rules-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Alert when rule processing failures exceed threshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.rules_dlq.name
  }

  tags = var.common_tags
}

# Lambda permissions for EventBridge
resource "aws_lambda_permission" "eventbridge_sigma_parser" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_sigma_parser.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sigma_parser_trigger.arn
}


resource "aws_lambda_permission" "eventbridge_universal_processor" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_universal_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.universal_processor_trigger.arn
}


# Elastic Parser Trigger
resource "aws_cloudwatch_event_rule" "elastic_parser_trigger" {
  name           = "trigger-elastic-parser"
  description    = "Trigger Elastic parser when rules downloaded"
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name

  event_pattern = jsonencode({
    source      = ["rules.downloader.elastic"]
    detail-type = ["com.security.rules.downloaded"]
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "elastic_parser" {
  rule           = aws_cloudwatch_event_rule.elastic_parser_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name
  target_id      = "elastic-parser"
  arn            = aws_lambda_function.pano_elastic_parser.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

# Snort Parser Trigger
resource "aws_cloudwatch_event_rule" "snort_parser_trigger" {
  name           = "trigger-snort-parser"
  description    = "Trigger Snort parser when rules downloaded"
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name

  event_pattern = jsonencode({
    source      = ["rules.downloader.snort"]
    detail-type = ["com.security.rules.downloaded"]
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "snort_parser" {
  rule           = aws_cloudwatch_event_rule.snort_parser_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name
  target_id      = "snort-parser"
  arn            = aws_lambda_function.pano_snort_parser.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

# MITRE Enricher Trigger
resource "aws_cloudwatch_event_rule" "mitre_enricher_trigger" {
  name           = "trigger-mitre-enricher"
  description    = "Trigger MITRE enricher when rules need enrichment"
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name

  event_pattern = jsonencode({
    source      = ["rules.processor"]
    detail-type = ["com.security.enrichment.mitre"]
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "mitre_enricher" {
  rule           = aws_cloudwatch_event_rule.mitre_enricher_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name
  target_id      = "mitre-enricher"
  arn            = aws_lambda_function.pano_mitre_enricher.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

# CVE Enricher Trigger
resource "aws_cloudwatch_event_rule" "cve_enricher_trigger" {
  name           = "trigger-cve-enricher"
  description    = "Trigger CVE enricher when rules need enrichment"
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name

  event_pattern = jsonencode({
    source      = ["rules.processor"]
    detail-type = ["com.security.enrichment.cve"]
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "cve_enricher" {
  rule           = aws_cloudwatch_event_rule.cve_enricher_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.rules_processing.name
  target_id      = "cve-enricher"
  arn            = aws_lambda_function.pano_cve_enricher.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

# Download Schedules
resource "aws_cloudwatch_event_rule" "elastic_download_schedule" {
  name                = "elastic-download-schedule"
  description         = "Schedule for automatic Elastic rule downloads"
  schedule_expression = "rate(24 hours)"
  state               = var.enable_auto_download ? "ENABLED" : "DISABLED"
  tags                = var.common_tags
}

resource "aws_cloudwatch_event_target" "elastic_downloader_scheduled" {
  rule      = aws_cloudwatch_event_rule.elastic_download_schedule.name
  target_id = "elastic-downloader"
  arn       = aws_lambda_function.pano_elastic_downloader.arn
}

resource "aws_cloudwatch_event_rule" "snort_download_schedule" {
  name                = "snort-download-schedule"
  description         = "Schedule for automatic Snort rule downloads"
  schedule_expression = "rate(12 hours)"
  state               = var.enable_auto_download ? "ENABLED" : "DISABLED"
  tags                = var.common_tags
}

resource "aws_cloudwatch_event_target" "snort_downloader_scheduled" {
  rule      = aws_cloudwatch_event_rule.snort_download_schedule.name
  target_id = "snort-downloader"
  arn       = aws_lambda_function.pano_snort_downloader.arn
}

resource "aws_cloudwatch_event_rule" "stix_update_schedule" {
  name                = "stix-update-schedule"
  description         = "Schedule for STIX data updates"
  schedule_expression = "rate(7 days)"
  state               = "ENABLED"
  tags                = var.common_tags
}

resource "aws_cloudwatch_event_target" "stix_processor_scheduled" {
  rule      = aws_cloudwatch_event_rule.stix_update_schedule.name
  target_id = "stix-processor"
  arn       = aws_lambda_function.pano_stix_processor.arn
}