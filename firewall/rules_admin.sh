#!/bin/sh
# B 담당: 작업 예정

set -e

# 관리자 PC에서만 SSH(22번 포트) 접속 허용
iptables -A INPUT -p tcp --dport 22 -s "$ADMIN_IP" -j ACCEPT

echo "[B] 관리자 IP($ADMIN_IP)의 SSH(22) 접속 허용"