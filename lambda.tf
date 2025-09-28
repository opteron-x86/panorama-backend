# lambda.tf

data "archive_file" "pano_api_handler" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-api-handler"
  output_path = "${path.module}/builds/pano-api-handler.zip"
}

resource "aws_lambda_function" "pano_api_handler" {
  function_name = "pano-api-handler"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 256
  timeout       = 30
  tags = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DISABLE_AUTH  = true
    }
  }
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  layers = [
    local.lambda_layers.dependencies,
    local.lambda_layers.datamodel,
    local.lambda_layers.jwt
  ]
  
  filename         = data.archive_file.pano_api_handler.output_path
  source_code_hash = data.archive_file.pano_api_handler.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_sigma_processor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-sigma-processor"
  output_path = "${path.module}/builds/pano-sigma-processor.zip"
}

resource "aws_lambda_function" "pano_sigma_processor" {
  function_name = "pano-sigma-processor"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 256
  timeout       = 210
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
    }
  }
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  layers = [
    local.lambda_layers.datamodel,
    local.lambda_layers.dependencies,
    local.lambda_layers.yaml,
  ]
  
  filename         = data.archive_file.pano_sigma_processor.output_path
  source_code_hash = data.archive_file.pano_sigma_processor.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_snort_processor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-snort-processor"
  output_path = "${path.module}/builds/pano-snort-processor.zip"
}

resource "aws_lambda_function" "pano_snort_processor" {
  function_name = "pano-snort-processor"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 256
  timeout       = 210
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
    }
  }
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  layers = [
    local.lambda_layers.datamodel,
    local.lambda_layers.dependencies,
  ]
  
  filename         = data.archive_file.pano_snort_processor.output_path
  source_code_hash = data.archive_file.pano_snort_processor.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_elastic_processor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-elastic-processor"
  output_path = "${path.module}/builds/pano-elastic-processor.zip"
}

resource "aws_lambda_function" "pano_elastic_processor" {
  function_name = "pano-elastic-processor"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 256
  timeout       = 210
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
    }
  }
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  layers = [
    local.lambda_layers.datamodel,
    local.lambda_layers.dependencies,
  ]
  
  filename         = data.archive_file.pano_elastic_processor.output_path
  source_code_hash = data.archive_file.pano_elastic_processor.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_community_downloader" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-community-downloader"
  output_path = "${path.module}/builds/pano-community-downloader.zip"
}

resource "aws_lambda_function" "pano_community_downloader" {
  function_name = "pano-community-downloader"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_dlrole_arn
  memory_size   = 256
  timeout       = 210
  tags          = var.common_tags
  layers = [
    local.lambda_layers.yaml,
  ]
  
  filename         = data.archive_file.pano_community_downloader.output_path
  source_code_hash = data.archive_file.pano_community_downloader.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_cve_enricher" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-cve-enricher"
  output_path = "${path.module}/builds/pano-cve-enricher.zip"
}

resource "aws_lambda_function" "pano_cve_enricher" {
  function_name = "pano-cve-enricher"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 256
  timeout       = 600
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
    }
  }
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  layers = [
    local.lambda_layers.datamodel,
    local.lambda_layers.dependencies,
  ]
  
  filename         = data.archive_file.pano_cve_enricher.output_path
  source_code_hash = data.archive_file.pano_cve_enricher.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_elastic_downloader" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-elastic-downloader"
  output_path = "${path.module}/builds/pano-elastic-downloader.zip"
}

resource "aws_lambda_function" "pano_elastic_downloader" {
  function_name = "pano-elastic-downloader"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_dlrole_arn
  memory_size   = 256
  timeout       = 300
  tags          = var.common_tags
  layers = [
    local.lambda_layers.toml,
  ]
  
  filename         = data.archive_file.pano_elastic_downloader.output_path
  source_code_hash = data.archive_file.pano_elastic_downloader.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_mitre_enricher" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-mitre-enricher"
  output_path = "${path.module}/builds/pano-mitre-enricher.zip"
}

resource "aws_lambda_function" "pano_mitre_enricher" {
  function_name = "pano-mitre-enricher"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 512
  timeout       = 300
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
    }
  }
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  layers = [
    local.lambda_layers.datamodel,
    local.lambda_layers.dependencies,
  ]
  
  filename         = data.archive_file.pano_mitre_enricher.output_path
  source_code_hash = data.archive_file.pano_mitre_enricher.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_snort_downloader" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-snort-downloader"
  output_path = "${path.module}/builds/pano-snort-downloader.zip"
}

resource "aws_lambda_function" "pano_snort_downloader" {
  function_name = "pano-snort-downloader"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_dlrole_arn
  memory_size   = 256
  timeout       = 300
  tags          = var.common_tags
  layers = [
    local.lambda_layers.dependencies,
  ]
  
  filename         = data.archive_file.pano_snort_downloader.output_path
  source_code_hash = data.archive_file.pano_snort_downloader.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}

data "archive_file" "pano_stix_processor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-functions/pano-stix-processor"
  output_path = "${path.module}/builds/pano-stix-processor.zip"
}

resource "aws_lambda_function" "pano_stix_processor" {
  function_name = "pano-stix-processor"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  role          = local.lambda_execrole_arn
  memory_size   = 256
  timeout       = 210
  tags          = var.common_tags

  environment {
    variables = {
      DB_HOST       = aws_db_instance.panorama.address
      DB_NAME       = aws_db_instance.panorama.db_name
      DB_SECRET_ARN = local.db_secret_arn
      DB_USER       = aws_db_instance.panorama.username
      DB_PORT       = 5432
    }
  }
  
  vpc_config {
    subnet_ids         = local.vpc_config.subnet_prv_ids
    security_group_ids = local.vpc_config.security_group_ids
  }
  
  layers = [
    local.lambda_layers.datamodel,
    local.lambda_layers.dependencies,
  ]
  
  filename         = data.archive_file.pano_stix_processor.output_path
  source_code_hash = data.archive_file.pano_stix_processor.output_base64sha256
  
  lifecycle {
    ignore_changes = []
  }
}