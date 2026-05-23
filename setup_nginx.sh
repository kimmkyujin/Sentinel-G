#!/bin/bash

# 사용법: ./setup_nginx.sh <도메인주소>
# 예시: ./setup_nginx.sh 34.123.45.67.nip.io

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "오류: 도메인 주소가 입력되지 않았습니다."
    echo "사용법: $0 <도메인주소>"
    exit 1
fi

echo "=========================================="
echo " Nginx 및 Let's Encrypt 자동 구축 스크립트"
echo " 대상 도메인: $DOMAIN"
echo "=========================================="

echo "[1/5] 내부 방화벽(UFW) 설정 중..."
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

echo "[2/5] 필수 패키지 설치 중..."
sudo apt update -y
sudo apt install -y nginx certbot python3-certbot-nginx

echo "[3/5] Nginx 리버스 프록시 설정 중..."
sudo bash -c "cat > /etc/nginx/sites-available/default" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

echo "[4/5] Nginx 문법 테스트 및 재시작..."
sudo nginx -t
if [ $? -ne 0 ]; then
    echo "Nginx 설정에 오류가 있습니다. 스크립트를 중단합니다."
    exit 1
fi
sudo systemctl restart nginx

echo "[5/5] Let's Encrypt HTTPS 인증서 자동 발급 및 적용 중..."
# 비대화형 모드로 Nginx 플러그인을 사용하여 인증서 발급 및 리다이렉트 설정 적용
sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --register-unsafely-without-email

echo "=========================================="
echo " 모든 설정이 완료되었습니다!"
echo " 이제 https://$DOMAIN 으로 접속하실 수 있습니다."
echo "=========================================="
