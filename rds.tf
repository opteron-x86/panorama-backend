# rds.tf
resource "aws_db_instance" "panorama" {
  identifier                    = "panorama-db-1"
  allocated_storage            = 20
  storage_type                 = "gp3"
  storage_throughput           = 125
  storage_encrypted            = true
  iops                        = 3000
  
  engine                       = "postgres"
  engine_version              = "17.4"
  instance_class              = "db.t4g.micro"
  
  db_name                     = local.db_config.db_name
  username                    = local.db_config.db_user
  
  db_subnet_group_name        = local.vpc_config.db_subnet_group
  vpc_security_group_ids      = local.vpc_config.db_security_group_id
  
  backup_retention_period     = 1
  backup_window              = "05:39-06:09"
  maintenance_window         = "fri:06:27-fri:06:57"
  
  performance_insights_enabled = true
  performance_insights_kms_key_id = local.db_config.perf_insights_kms
  performance_insights_retention_period = 7
  
  skip_final_snapshot        = true
  deletion_protection        = false
  
  copy_tags_to_snapshot = true
  max_allocated_storage = 1000
  
  lifecycle {
    ignore_changes = [password]
  }
}