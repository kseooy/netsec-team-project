#!/bin/sh
# 팀장 담당: 추가 보안 기능
# ① SSH 무차별 대입 차단  ② 비정상 스캔 패킷 차단  ③ 웹 DoS 완화
# ※ rules_basic.sh(A), rules_admin.sh(B) 다음에 실행됨
#   규칙을 체인(묶음)으로 만든 뒤, 기존 규칙보다 "앞"에 끼워 넣는 방식 (-I)
set -e

# ─────────────────────────────────────────────
# ② 비정상 스캔 패킷 차단 (SCAN_BLOCK)
#    정상 통신에서는 나오지 않는 TCP 플래그 조합 = 포트 스캔 도구가 쓰는 패킷
# ─────────────────────────────────────────────
iptables -N SCAN_BLOCK
iptables -A SCAN_BLOCK -p tcp --tcp-flags ALL NONE        -j DROP   # NULL 스캔 (플래그 없음)
iptables -A SCAN_BLOCK -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP   # XMAS 스캔
iptables -A SCAN_BLOCK -p tcp --tcp-flags ALL FIN         -j DROP   # FIN 스캔
iptables -A SCAN_BLOCK -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP   # SYN+FIN 동시 (비정상)
iptables -A SCAN_BLOCK -p tcp --tcp-flags SYN,RST SYN,RST -j DROP   # SYN+RST 동시 (비정상)
iptables -A SCAN_BLOCK -p tcp ! --syn -m conntrack --ctstate NEW -j DROP  # SYN 없이 시작하는 새 연결 (ACK 스캔 등)
iptables -A SCAN_BLOCK -m conntrack --ctstate INVALID     -j DROP   # 상태가 맞지 않는 패킷

# ─────────────────────────────────────────────
# ① SSH 무차별 대입 차단 (SSH_GUARD)
#    같은 IP가 60초 안에 SSH 새 접속을 4번 이상 시도하면 차단
#    (C의 MaxAuthTries는 "접속 1번 안에서" 비밀번호 3회 제한 → 이건 "재접속 자체"를 제한)
# ─────────────────────────────────────────────
iptables -N SSH_GUARD
iptables -A SSH_GUARD -m recent --name ssh_try --set
iptables -A SSH_GUARD -m recent --name ssh_try --update --seconds 60 --hitcount 4 -j DROP

# ─────────────────────────────────────────────
# ③ 웹 DoS 완화 (WEB_LIMIT)
#    한 IP가 웹서버로 여는 연결 수와 속도를 제한
# ─────────────────────────────────────────────
iptables -N WEB_LIMIT
iptables -A WEB_LIMIT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP   # IP당 동시 연결 10개 초과 차단
iptables -A WEB_LIMIT -m hashlimit --hashlimit-name web_rate --hashlimit-mode srcip \
  --hashlimit-above 10/second --hashlimit-burst 20 -j DROP                                  # IP당 초당 새 연결 10개 초과 차단 (순간 20개까지 허용)

# ─────────────────────────────────────────────
# 기존 규칙 앞에 끼워 넣기
# ─────────────────────────────────────────────
iptables -I INPUT 1 -i "$EXT_IF" -j SCAN_BLOCK
iptables -I INPUT 2 -i "$EXT_IF" -p tcp --dport 22 -m conntrack --ctstate NEW -j SSH_GUARD

iptables -I FORWARD 1 -i "$EXT_IF" -j SCAN_BLOCK
iptables -I FORWARD 2 -i "$EXT_IF" -p tcp -d "$WEB_IP" --dport 80 -m conntrack --ctstate NEW -j WEB_LIMIT

echo "[추가 보안] 스캔 차단 / SSH 무차별 대입 차단 / 웹 DoS 완화 적용 완료"
