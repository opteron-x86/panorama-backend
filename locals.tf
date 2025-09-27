locals {
  lambda_execrole_arn = "arn:aws:iam::538269499906:role/panorama-lambda-exec-role"
  lambda_dlrole_arn = "arn:aws:iam::538269499906:role/service-role/pano-community-downloader-role-hgmmhwlz"
  db_secret_arn   = "arn:aws:secretsmanager:us-east-2:538269499906:secret:rds!db-99db52c2-1139-4a27-a78c-467ee9a6da0c-UDYSKg"
  
  vpc_config = {
    subnet_prv_ids         = ["subnet-0026c39860281ced1", "subnet-0dcff8fbea9ddd947"]
    subnet_pub_ids         = ["subnet-0fd72cc56e1b5404d", "subnet-0928c284535fb8480"]
    security_group_ids = ["sg-09cf54948f08637f0"]
    db_security_group_id    = ["sg-06ecc5fa0436a7610"]
    db_subnet_group     = ["default-vpc-06f331697458252ad"]
  }

  db_config = {
    db_name     = "PanoDB"
    db_user     = "pgadmin"
    perf_insights_kms = "arn:aws:kms:us-east-2:538269499906:key/b090e6e9-6ad0-45e7-aac2-9195f39bec78"
  }
  
  db_security_group_id = "sg-06ecc5fa0436a7610"
  db_subnet_group     = "default-vpc-06f331697458252ad"
  
  lambda_layers = {
    datamodel     = "arn:aws:lambda:us-east-2:538269499906:layer:panorama_datamodel:4"
    dependencies  = "arn:aws:lambda:us-east-2:538269499906:layer:panorama_dependencies:1"
    yaml         = "arn:aws:lambda:us-east-2:538269499906:layer:yaml:1"
    jwt          = "arn:aws:lambda:us-east-2:538269499906:layer:jwt:1"
    toml         = "arn:aws:lambda:us-east-2:538269499906:layer:toml:1"
  }
}