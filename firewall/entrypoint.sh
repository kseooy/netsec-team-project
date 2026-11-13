#!/bin/sh
set -e

# IP로 외부/내부 인터페이스 이름 찾기 (eth0/eth1 순서가 바뀔 수 있어서)
find_if() {
  ip -o -4 addr show | awk -v ip="$1" '{split($4,a,"/"); if (a[1]==ip) print $2}'
}
export EXT_IF=$(find_if "$EXT_IP")
export INT_IF=$(find_if "$INT_IP")
echo "[정보] 외부: $EXT_IF / 내부: $INT_IF"

/fw/setup_ssh.sh     # C
/fw/rules_basic.sh   # A
/fw/rules_admin.sh   # B
/fw/rules_extra.sh   # 팀장 (추가 보안)

iptables -L -n -v
iptables -t nat -L -n -v

# C가 SSH 설정을 끝냈으면 SSH 서버 실행, 아니면 그냥 켜진 상태 유지
if [ -f /etc/ssh/ssh_host_ed25519_key ]; then
  exec /usr/sbin/sshd -D -e
else
  echo "[정보] SSH 미설정 (C 작업 전)"
  exec sleep infinity
fi