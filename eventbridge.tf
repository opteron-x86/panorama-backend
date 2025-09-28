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

# Lambda function definitions updates
resource "aws_lambda_function" "pano_sigma_parser" {
  function_name = "pano-sigma-parser"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 120
  tags          = var.common_tags

  environment {
    variables = {
      STAGING_BUCKET = aws_s3_bucket.staging.bucket
      EVENT_BUS      = aws_cloudwatch_event_bus.rules_processing.name
    }
  }

  layers = [
    local.lambda_layers.dependencies
  ]

  filename         = data.archive_file.pano_sigma_parser.output_path
  source_code_hash = data.archive_file.pano_sigma_parser.output_base64sha256
}

resource "aws_lambda_function" "pano_universal_processor" {
  function_name = "pano-universal-processor"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 1024
  timeout       = 300
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
      EVENT_BUS     = aws_cloudwatch_event_bus.rules_processing.name
      BATCH_SIZE    = 100
    }
  }

  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }

  layers = [
    local.lambda_layers.datamodel,
    local.lambda_layers.dependencies
  ]

  filename         = data.archive_file.pano_universal_processor.output_path
  source_code_hash = data.archive_file.pano_universal_processor.output_base64sha256
}