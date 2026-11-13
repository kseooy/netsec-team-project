#!/bin/sh
# 팀장 담당: 추가 보안 기능
# ① SSH 무차별 대입 차단  ② 비정상 스캔 패킷 차단  ③ 웹 DoS 완화  ④ 차단 로그 기록
# ※ rules_basic.sh(A), rules_admin.sh(B) 다음에 실행됨
#   규칙을 체인(묶음)으로 만든 뒤, 기존 규칙보다 "앞"에 끼워 넣는 방식 (-I)
set -e

LOG_FILE=/var/log/firewall_drop.log

# ─────────────────────────────────────────────
# ④ 차단 로그 준비 (ulogd)
#    컨테이너 안에서는 일반 LOG 기록이 보이지 않아서,
#    NFLOG로 차단 패킷을 넘기고 ulogd가 받아서 파일로 기록하는 방식
# ─────────────────────────────────────────────
PLUGDIR=$(dirname "$(find /usr/lib -name 'ulogd_inppkt_NFLOG.so' 2>/dev/null | head -1)")
cat > /etc/ulogd-fw.conf <<CONF
[global]
logfile="/var/log/ulogd.log"
loglevel=3
plugin="$PLUGDIR/ulogd_inppkt_NFLOG.so"
plugin="$PLUGDIR/ulogd_raw2packet_BASE.so"
plugin="$PLUGDIR/ulogd_filter_IFINDEX.so"
plugin="$PLUGDIR/ulogd_filter_IP2STR.so"
plugin="$PLUGDIR/ulogd_filter_PRINTPKT.so"
plugin="$PLUGDIR/ulogd_output_LOGEMU.so"
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU

[log1]
group=1

[emu1]
file="$LOG_FILE"
sync=1
CONF
touch "$LOG_FILE"
if ulogd -d -c /etc/ulogd-fw.conf; then
  # 차단 기록을 docker logs(Docker Desktop Logs 탭)에도 실시간으로 표시
  tail -n 0 -F "$LOG_FILE" &
  echo "[로그] 차단 로그 기록 시작 ($LOG_FILE)"
else
  echo "[로그] ulogd 실행 실패 - 차단 기능은 그대로 동작하고 로그만 기록되지 않음"
fi

# 차단하기 전에 로그를 남기는 함수
#   사용법: log_drop 체인이름 로그태그 [조건...]
#   로그는 초당 5건(순간 10건)까지만 기록 → 공격이 몰려도 로그 때문에 방화벽이 느려지지 않게
log_drop() {
  chain=$1; tag=$2; shift 2
  iptables -A "$chain" "$@" -m limit --limit 5/second --limit-burst 10 \
    -j NFLOG --nflog-group 1 --nflog-prefix "[DROP:$tag] "
  iptables -A "$chain" "$@" -j DROP
}

# ─────────────────────────────────────────────
# ② 비정상 스캔 패킷 차단 (SCAN_BLOCK)
#    정상 통신에서는 나오지 않는 TCP 플래그 조합 = 포트 스캔 도구가 쓰는 패킷
# ─────────────────────────────────────────────
iptables -N SCAN_BLOCK
log_drop SCAN_BLOCK SCAN_NULL    -p tcp --tcp-flags ALL NONE                     # NULL 스캔 (플래그 없음)
log_drop SCAN_BLOCK SCAN_XMAS    -p tcp --tcp-flags ALL FIN,PSH,URG              # XMAS 스캔
log_drop SCAN_BLOCK SCAN_FIN     -p tcp --tcp-flags ALL FIN                      # FIN 스캔
log_drop SCAN_BLOCK SCAN_SYNFIN  -p tcp --tcp-flags SYN,FIN SYN,FIN              # SYN+FIN 동시 (비정상)
log_drop SCAN_BLOCK SCAN_SYNRST  -p tcp --tcp-flags SYN,RST SYN,RST              # SYN+RST 동시 (비정상)
log_drop SCAN_BLOCK SCAN_NOSYN   -p tcp ! --syn -m conntrack --ctstate NEW       # SYN 없이 시작하는 새 연결 (ACK 스캔 등)
log_drop SCAN_BLOCK INVALID      -m conntrack --ctstate INVALID                  # 상태가 맞지 않는 패킷

# ─────────────────────────────────────────────
# ① SSH 무차별 대입 차단 (SSH_GUARD)
#    같은 IP가 60초 안에 SSH 새 접속을 4번 이상 시도하면 차단
#    (C의 MaxAuthTries는 "접속 1번 안에서" 비밀번호 3회 제한 → 이건 "재접속 자체"를 제한)
# ─────────────────────────────────────────────
iptables -N SSH_GUARD
iptables -A SSH_GUARD -m recent --name ssh_try --set
log_drop SSH_GUARD SSH_BRUTE -m recent --name ssh_try --update --seconds 60 --hitcount 4

# ─────────────────────────────────────────────
# ③ 웹 DoS 완화 (WEB_LIMIT)
#    한 IP가 웹서버로 여는 연결 수와 속도를 제한
# ─────────────────────────────────────────────
iptables -N WEB_LIMIT
log_drop WEB_LIMIT WEB_CONNLIMIT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 32   # IP당 동시 연결 10개 초과
log_drop WEB_LIMIT WEB_RATE -m hashlimit --hashlimit-name web_rate --hashlimit-mode srcip \
  --hashlimit-above 10/second --hashlimit-burst 20                                             # IP당 초당 새 연결 10개 초과 (순간 20개까지 허용)

# ─────────────────────────────────────────────
# 기존 규칙 앞에 끼워 넣기
# ─────────────────────────────────────────────
iptables -I INPUT 1 -i "$EXT_IF" -j SCAN_BLOCK
iptables -I INPUT 2 -i "$EXT_IF" -p tcp --dport 22 -m conntrack --ctstate NEW -j SSH_GUARD

iptables -I FORWARD 1 -i "$EXT_IF" -j SCAN_BLOCK
iptables -I FORWARD 2 -i "$EXT_IF" -p tcp -d "$WEB_IP" --dport 80 -m conntrack --ctstate NEW -j WEB_LIMIT

# ─────────────────────────────────────────────
# ④ 기본 정책(DROP)으로 버려지는 패킷도 기록
#    맨 마지막에 추가 → 위의 어떤 허용 규칙에도 해당하지 않은 패킷만 여기까지 옴
#    (예: 일반 PC의 SSH 접속 시도, 열리지 않은 포트 접근)
# ─────────────────────────────────────────────
iptables -A INPUT   -m limit --limit 5/second --limit-burst 10 -j NFLOG --nflog-group 1 --nflog-prefix "[DROP:INPUT_POLICY] "
iptables -A FORWARD -m limit --limit 5/second --limit-burst 10 -j NFLOG --nflog-group 1 --nflog-prefix "[DROP:FORWARD_POLICY] "

echo "[추가 보안] 스캔 차단 / SSH 무차별 대입 차단 / 웹 DoS 완화 / 차단 로그 적용 완료"
