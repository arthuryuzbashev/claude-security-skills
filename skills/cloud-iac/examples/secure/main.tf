resource "aws_s3_bucket" "assets" {
  bucket = "example-test-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks     = ["198.51.100.0/24"] # office VPN
  }
}

data "aws_iam_policy_document" "ci" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
  }
}

resource "aws_db_instance" "main" {
  identifier                  = "app-db"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  username                    = "app"
  manage_master_user_password = true
  publicly_accessible         = false
  storage_encrypted           = true
}

resource "aws_instance" "worker" {
  ami           = "ami-00000000000000000"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }
}

resource "aws_kms_key" "app" {
  description         = "app data key"
  enable_key_rotation = true
}

resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::123456789012:role/eks"

  vpc_config {
    subnet_ids              = ["subnet-00000000"]
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}

resource "aws_cloudtrail" "main" {
  name                       = "main"
  s3_bucket_name             = "example-test-trail"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}
