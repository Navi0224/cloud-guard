# DELIBERATELY INSECURE example - for testing cloud-guard only. Do not apply.

# TF-SG-001: SSH and RDP open to the whole internet (inline ingress blocks)
resource "aws_security_group" "admin" {
  name        = "admin-access"
  description = "Too permissive"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# TF-SG-001: "all traffic" from IPv6 anywhere, as a standalone rule resource
resource "aws_security_group_rule" "all_ipv6" {
  type              = "ingress"
  security_group_id = aws_security_group.admin.id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  ipv6_cidr_blocks  = ["::/0"]
}

# TF-SG-001: the newer per-rule resource type, port range 20-25 includes 22
resource "aws_vpc_security_group_ingress_rule" "ssh_range" {
  security_group_id = aws_security_group.admin.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 20
  to_port           = 25
  ip_protocol       = "tcp"
}
