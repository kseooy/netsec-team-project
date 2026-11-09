#!/bin/sh
# C 담당: 전하림 (SSH 서버 설정, 관리자 ID/PW, root 로그인 금지, 로그인 시도 횟수 제한)
set -e

echo "[C] SSH 서버 및 보안 설정 시작..."

# 1. SSH 호스트 키 생성 (sshd 실행 필수 조건)
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

# 2. 관리자 계정 생성 (.env 의 ADMIN_USER 환경변수 활용)
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
    adduser -D "$ADMIN_USER"
fi

# 3. 관리자 비밀번호 설정 (.env 의 ADMIN_PASSWORD 환경변수 활용)
echo "$ADMIN_USER:$ADMIN_PASSWORD" | chpasswd

# 4. SSHD 보안 설정 적용 (sshd_config)
# - root 로그인 차단 (PermitRootLogin no)
# - 비밀번호 인증 허용 (PasswordAuthentication yes)
# - MaxAuthTries 3 (로그인 시도 횟수 3회 제한)
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

if grep -q "^MaxAuthTries" /etc/ssh/sshd_config; then
    sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
else
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
fi

echo "[C] SSH 서버 및 관리자 계정($ADMIN_USER) 보안 설정 완료"