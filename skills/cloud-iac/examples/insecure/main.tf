provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
}

resource "aws_s3_bucket" "assets" {
  bucket = "example-test-assets"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    description = "ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "pg" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

resource "aws_iam_policy" "ci" {
  name = "ci-deployer"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "main" {
  identifier          = "app-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "app"
  password            = "SuperSecret-not-real-1"
  publicly_accessible = true
}

resource "aws_instance" "worker" {
  ami           = "ami-00000000000000000"
  instance_type = "t3.micro"

  root_block_device {
    volume_size = 20
  }
}

resource "aws_kms_key" "app" {
  description = "app data key"
}

resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::123456789012:role/eks"

  vpc_config {
    subnet_ids = ["subnet-00000000"]
  }
}

resource "aws_lambda_function_url" "hook" {
  function_name      = "hook"
  authorization_type = "NONE"
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  s3_bucket_name = "example-test-trail"
}
