# Intentionally insecure AWS configuration — used for testing only

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-insecure-bucket"
  # No public access block
  # No encryption
  # No versioning
  # No logging
}

resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Dangerously open security group"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "admin_role" {
  name = "admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "wildcard_policy" {
  name = "wildcard-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "main_db" {
  identifier            = "main-db"
  engine                = "mysql"
  instance_class        = "db.t3.micro"
  allocated_storage     = 20
  username              = "admin"
  password              = "insecure123"
  publicly_accessible   = true
  storage_encrypted     = false
  deletion_protection   = false
  backup_retention_period = 0
  skip_final_snapshot   = true
}

resource "aws_eks_cluster" "main_cluster" {
  name     = "main-cluster"
  role_arn = aws_iam_role.admin_role.arn

  vpc_config {
    subnet_ids              = ["subnet-12345678"]
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }
  # No encryption_config
}

resource "aws_cloudtrail" "main_trail" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.data_bucket.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
}

resource "aws_kms_key" "main_key" {
  description         = "Main KMS key"
  enable_key_rotation = false
}

resource "aws_lambda_function" "processor" {
  filename      = "processor.zip"
  function_name = "data-processor"
  role          = aws_iam_role.admin_role.arn
  handler       = "main.handler"
  runtime       = "python3.11"
  # No vpc_config
}

resource "aws_instance" "web_server" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  root_block_device {
    volume_size = 20
    encrypted   = false
  }

  # No metadata_options — IMDSv1 is active by default
}
