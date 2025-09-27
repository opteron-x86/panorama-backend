# outputs.tf
output "api_gateway_url" {
  value = "https://${aws_api_gateway_rest_api.panorama.id}.execute-api.us-east-2.amazonaws.com"
}

output "database_endpoint" {
  value = aws_db_instance.panorama.endpoint
}

output "cognito_pool_id" {
  value = aws_cognito_user_pool.main.id
}