# Synthetic fixture for the Hullproof Engine scanner adapter tests. Every setting here is wrong on purpose.
provider "aws" {
  region = "eu-west-1"
}

variable "db_password" {
  default = "fixture-password-not-real"
}

resource "aws_s3_bucket" "uploads" {
  bucket = "hullproof-fixture-uploads"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "db" {
  name        = "db"
  description = "database"
  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_iam_policy" "deploy" {
  name = "deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 10
  encrypted         = false
}

resource "aws_cloudtrail" "main" {
  name                       = "main"
  s3_bucket_name             = aws_s3_bucket.uploads.id
  is_multi_region_trail      = false
  enable_log_file_validation = false
}
