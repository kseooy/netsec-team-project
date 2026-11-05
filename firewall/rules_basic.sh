# A 담당: 방화벽 기본 정책 (웹서비스 외 전부 차단)
set -e

# 1. 기존 규칙 초기화
iptables -F
iptables -X

# 2. 기본 정책: 들어오는 것·통과하는 것 전부 차단
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. 방화벽 자기 자신(loopback) 통신 허용
iptables -A INPUT -i lo -j ACCEPT

# 4. 이미 허용된 연결의 응답 패킷 통과
iptables -A INPUT   -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 5. 외부에서 방화벽:80 으로 온 요청 → 웹서버:80 으로 주소 변환 (DNAT)
iptables -t nat -A PREROUTING -i "$EXT_IF" -p tcp --dport 80 \
  -j DNAT --to-destination "$WEB_IP:80"

# 6. DNAT된 연결만 웹서버로 통과 (웹서버 IP로 직접 오는 건 차단)
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -p tcp -d "$WEB_IP" --dport 80 \
  -m conntrack --ctstate NEW,DNAT -j ACCEPT

# 7. 웹서버 응답이 방화벽으로 돌아오게 출발지 주소 변환
iptables -t nat -A POSTROUTING -o "$INT_IF" -p tcp -d "$WEB_IP" --dport 80 -j MASQUERADE

echo "[A] 기본 방화벽 규칙 적용 완료"