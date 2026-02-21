# Example: AWS infrastructure with security issues that threatmap will flag

resource "aws_s3_bucket" "app_data" {
  bucket = "my-app-data-bucket"
}

resource "aws_security_group" "web_sg" {
  name   = "web-sg"
  vpc_id = "vpc-abc12345"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # flagged: SSH open to world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  root_block_device {
    volume_size = 20
    encrypted   = false   # flagged: unencrypted root volume
  }

  # flagged: metadata_options absent — IMDSv1 enabled
}

resource "aws_db_instance" "app_db" {
  identifier        = "app-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "appuser"
  password          = "changeme"

  publicly_accessible     = false
  storage_encrypted       = true
  deletion_protection     = true
  backup_retention_period = 7
  skip_final_snapshot     = false
}
