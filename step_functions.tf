resource "aws_sfn_state_machine" "mitre_enrichment" {
  name     = "panorama-mitre-enrichment"
  role_arn = aws_iam_role.step_functions.arn
  
  definition = jsonencode({
    Comment = "Process MITRE enrichment in parallel"
    StartAt = "CreateChunks"
    States = {
      CreateChunks = {
        Type     = "Task"
        Resource = aws_lambda_function.pano_mitre_orchestrator.arn
        Next     = "ProcessInParallel"
      }
      ProcessInParallel = {
        Type           = "Map"
        MaxConcurrency = 3  # Run 10 workers at once
        ItemsPath      = "$.chunks"
        Iterator = {
          StartAt = "ProcessChunk"
          States = {
            ProcessChunk = {
              Type     = "Task" 
              Resource = aws_lambda_function.pano_mitre_worker.arn
              End      = true
            }
          }
        }
        End = true
      }
    }
  })
}

# IAM role for Step Functions
resource "aws_iam_role" "step_functions" {
  name = "panorama-step-functions-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })
}


resource "aws_iam_role_policy_attachment" "step_functions_lambda" {
  role       = aws_iam_role.step_functions.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaRole"
}

# Allow Step Functions to invoke Lambdas
resource "aws_iam_role_policy" "step_functions_invoke" {
  role = aws_iam_role.step_functions.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "lambda:InvokeFunction"
      Resource = [
        aws_lambda_function.pano_mitre_orchestrator.arn,
        aws_lambda_function.pano_mitre_worker.arn
      ]
    }]
  })
}