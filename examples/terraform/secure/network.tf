# Admin access only from the corporate VPN range; HTTPS open to the world is fine.

resource "aws_security_group" "web" {
  name        = "web"
  description = "HTTPS from anywhere, SSH from VPN only"

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from VPN"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "rdp_from_vpn" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "10.20.0.0/16"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
}
