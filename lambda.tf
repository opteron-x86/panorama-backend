# lambda.tf

# Archive files for Lambda deployments
data "archive_file" "pano_universal_processor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-universal-processor"
  output_path = "${path.module}/builds/pano-universal-processor.zip"
}

data "archive_file" "pano_sigma_parser" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-sigma-parser"
  output_path = "${path.module}/builds/pano-sigma-parser.zip"
}

data "archive_file" "pano_sigma_downloader" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-sigma-downloader"
  output_path = "${path.module}/builds/pano-sigma-downloader.zip"
}

data "archive_file" "pano_elastic_parser" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-elastic-parser"
  output_path = "${path.module}/builds/pano-elastic-parser.zip"
}

data "archive_file" "pano_elastic_downloader" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-elastic-downloader"
  output_path = "${path.module}/builds/pano-elastic-downloader.zip"
}

data "archive_file" "pano_snort_parser" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-snort-parser"
  output_path = "${path.module}/builds/pano-snort-parser.zip"
}

data "archive_file" "pano_snort_downloader" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-snort-downloader"
  output_path = "${path.module}/builds/pano-snort-downloader.zip"
}

data "archive_file" "pano_mitre_enricher" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-mitre-enricher"
  output_path = "${path.module}/builds/pano-mitre-enricher.zip"
}

data "archive_file" "pano_cve_enricher" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-cve-enricher"
  output_path = "${path.module}/builds/pano-cve-enricher.zip"
}

data "archive_file" "pano_api_handler" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-api-handler"
  output_path = "${path.module}/builds/pano-api-handler.zip"
}

data "archive_file" "pano_stix_processor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-stix-processor"
  output_path = "${path.module}/builds/pano-stix-processor.zip"
}

data "archive_file" "pano_mitre_orchestrator" {
  type        = "zip"
  source_dir = "${path.module}/lambda-functions/pano-mitre-orchestrator"
  output_path = "${path.module}/builds/pano-mitre-orchestrator.zip"
}

data "archive_file" "pano_mitre_worker" {
  type        = "zip"
  source_dir = "${path.module}/lambda-functions/pano-mitre-worker"
  output_path = "${path.module}/builds/pano-mitre-worker.zip"
}

# Universal Processor
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
    }
  }

  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }

  layers = [
    local.lambda_layers.yaml,
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel
  ]

  filename         = data.archive_file.pano_universal_processor.output_path
  source_code_hash = data.archive_file.pano_universal_processor.output_base64sha256
}

# Sigma Downloader
resource "aws_lambda_function" "pano_sigma_downloader" {
  function_name = "pano-sigma-downloader"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 180
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

  filename         = data.archive_file.pano_sigma_downloader.output_path
  source_code_hash = data.archive_file.pano_sigma_downloader.output_base64sha256
}

# Sigma Parser
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
    local.lambda_layers.dependencies,
    local.lambda_layers.yaml
  ]

  filename         = data.archive_file.pano_sigma_parser.output_path
  source_code_hash = data.archive_file.pano_sigma_parser.output_base64sha256
}

# Elastic Downloader
resource "aws_lambda_function" "pano_elastic_downloader" {
  function_name = "pano-elastic-downloader"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 180
  tags          = var.common_tags

  environment {
    variables = {
      STAGING_BUCKET = aws_s3_bucket.staging.bucket
      EVENT_BUS      = aws_cloudwatch_event_bus.rules_processing.name
      GITHUB_TOKEN   = var.github_token
    }
  }

  layers = [
    local.lambda_layers.dependencies
  ]

  filename         = data.archive_file.pano_elastic_downloader.output_path
  source_code_hash = data.archive_file.pano_elastic_downloader.output_base64sha256
}

# Elastic Parser
resource "aws_lambda_function" "pano_elastic_parser" {
  function_name = "pano-elastic-parser"
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
    local.lambda_layers.dependencies,
    local.lambda_layers.toml
  ]

  filename         = data.archive_file.pano_elastic_parser.output_path
  source_code_hash = data.archive_file.pano_elastic_parser.output_base64sha256
}

# Snort Downloader
resource "aws_lambda_function" "pano_snort_downloader" {
  function_name = "pano-snort-downloader"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 180
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

  filename         = data.archive_file.pano_snort_downloader.output_path
  source_code_hash = data.archive_file.pano_snort_downloader.output_base64sha256
}

# Snort Parser
resource "aws_lambda_function" "pano_snort_parser" {
  function_name = "pano-snort-parser"
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

  filename         = data.archive_file.pano_snort_parser.output_path
  source_code_hash = data.archive_file.pano_snort_parser.output_base64sha256
}

# MITRE Enricher
resource "aws_lambda_function" "pano_mitre_enricher" {
  function_name = "pano-mitre-enricher"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 120
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
      EVENT_BUS     = aws_cloudwatch_event_bus.rules_processing.name
    }
  }

  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }

  layers = [
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel,
    local.lambda_layers.numpy,
    local.lambda_layers.onnx
  ]

  filename         = data.archive_file.pano_mitre_enricher.output_path
  source_code_hash = data.archive_file.pano_mitre_enricher.output_base64sha256
}

# CVE Enricher
resource "aws_lambda_function" "pano_cve_enricher" {
  function_name = "pano-cve-enricher"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 600
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
      NVD_API_KEY   = var.nvd_api_key
    }
  }

  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }

  layers = [
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel
  ]

  filename         = data.archive_file.pano_cve_enricher.output_path
  source_code_hash = data.archive_file.pano_cve_enricher.output_base64sha256
}

# API Handler
resource "aws_lambda_function" "pano_api_handler" {
  function_name = "pano-api-handler"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 256
  timeout       = 30
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST         = aws_db_instance.panorama.address
      DB_NAME         = aws_db_instance.panorama.db_name
      DB_SECRET_ARN   = local.db_secret_arn
      DB_USER         = aws_db_instance.panorama.username
      DB_PORT         = 5432
      CORS_ORIGIN     = var.cors_origin
      ENABLE_CACHING  = "true"
      CACHE_TTL       = "300"
      COGNITO_USER_POOL_ID = local.cognito_user_pool_id
      COGNITO_CLIENT_ID = local.cognito_client_id
      DISABLE_AUTH = false
    }
  }

  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }

  layers = [
    local.lambda_layers.jwt,
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel
  ]

  filename         = data.archive_file.pano_api_handler.output_path
  source_code_hash = data.archive_file.pano_api_handler.output_base64sha256
}

# STIX Processor
resource "aws_lambda_function" "pano_stix_processor" {
  function_name = "pano-stix-processor"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 1024
  timeout       = 300
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST        = aws_db_instance.panorama.address
      DB_NAME        = aws_db_instance.panorama.db_name
      DB_SECRET_ARN  = local.db_secret_arn
      DB_USER        = aws_db_instance.panorama.username
      DB_PORT        = 5432
      STAGING_BUCKET = aws_s3_bucket.staging.bucket
      EVENT_BUS      = aws_cloudwatch_event_bus.rules_processing.name
    }
  }

  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }

  layers = [
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel,
    # local.lambda_layers.stix
  ]

  filename         = data.archive_file.pano_stix_processor.output_path
  source_code_hash = data.archive_file.pano_stix_processor.output_base64sha256
}

# Worker Lambda - processes 100 rules at a time
resource "aws_lambda_function" "pano_mitre_worker" {
  function_name = "pano-mitre-worker"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 300  # 5 minutes per chunk
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
    }
  }
  
  layers = [
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel,
    local.lambda_layers.numpy
  ]
  
  filename         = data.archive_file.pano_mitre_worker.output_path
  source_code_hash = data.archive_file.pano_mitre_worker.output_base64sha256
}

# Orchestrator - just creates work chunks
resource "aws_lambda_function" "pano_mitre_orchestrator" {
  function_name = "pano-mitre-orchestrator"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 30 
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
    }
  }
  
  layers = [
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel,
    local.lambda_layers.numpy
  ]
  
  filename         = data.archive_file.pano_mitre_worker.output_path
  source_code_hash = data.archive_file.pano_mitre_worker.output_base64sha256
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "universal_processor" {
  name              = "/aws/lambda/pano-universal-processor"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "sigma_downloader" {
  name              = "/aws/lambda/pano-sigma-downloader"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "sigma_parser" {
  name              = "/aws/lambda/pano-sigma-parser"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "elastic_downloader" {
  name              = "/aws/lambda/pano-elastic-downloader"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "elastic_parser" {
  name              = "/aws/lambda/pano-elastic-parser"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "snort_downloader" {
  name              = "/aws/lambda/pano-snort-downloader"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "snort_parser" {
  name              = "/aws/lambda/pano-snort-parser"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "mitre_enricher" {
  name              = "/aws/lambda/pano-mitre-enricher"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "cve_enricher" {
  name              = "/aws/lambda/pano-cve-enricher"
  retention_in_days = 14
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "api_handler" {
  name              = "/aws/lambda/pano-api-handler"
  retention_in_days = 30
  tags              = var.common_tags
}

resource "aws_cloudwatch_log_group" "stix_processor" {
  name              = "/aws/lambda/pano-stix-processor"
  retention_in_days = 14
  tags              = var.common_tags
}

# Lambda Permissions for EventBridge
resource "aws_lambda_permission" "universal_processor_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_universal_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.universal_processor_trigger.arn
}

resource "aws_lambda_permission" "sigma_parser_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_sigma_parser.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sigma_parser_trigger.arn
}

resource "aws_lambda_permission" "elastic_parser_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_elastic_parser.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.elastic_parser_trigger.arn
}

resource "aws_lambda_permission" "snort_parser_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_snort_parser.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.snort_parser_trigger.arn
}

resource "aws_lambda_permission" "mitre_enricher_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_mitre_enricher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.mitre_enricher_trigger.arn
}

resource "aws_lambda_permission" "cve_enricher_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_cve_enricher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cve_enricher_trigger.arn
}

resource "aws_lambda_permission" "sigma_downloader_scheduled" {
  statement_id  = "AllowEventBridgeScheduledInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_sigma_downloader.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sigma_download_schedule.arn
}

resource "aws_lambda_permission" "elastic_downloader_scheduled" {
  statement_id  = "AllowEventBridgeScheduledInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_elastic_downloader.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.elastic_download_schedule.arn
}

resource "aws_lambda_permission" "snort_downloader_scheduled" {
  statement_id  = "AllowEventBridgeScheduledInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_snort_downloader.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.snort_download_schedule.arn
}

resource "aws_lambda_permission" "stix_processor_scheduled" {
  statement_id  = "AllowEventBridgeScheduledInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_stix_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.stix_update_schedule.arn
}

# API Gateway permission for API Handler
resource "aws_lambda_permission" "api_handler_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pano_api_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.panorama.execution_arn}/*/*"
}