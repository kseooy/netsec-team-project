FROM alpine:3.20
RUN apk add --no-cache iptables openssh iproute2
COPY *.sh /fw/
RUN sed -i 's/\r$//' /fw/*.sh && chmod +x /fw/*.sh
ENTRYPOINT ["/fw/entrypoint.sh"]