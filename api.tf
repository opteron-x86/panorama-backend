# api.tf
resource "aws_api_gateway_rest_api" "panorama" {
  name                     = "Panorama API"
  description              = "Security detection rules and threat intelligence API"
  minimum_compression_size = 1024
  
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}