FROM alpine:3.20
RUN apk add --no-cache openssh && \
    adduser -D -s /bin/sh crown && echo 'crown:crown' | chpasswd && \
    mkdir -p /run/sshd /home/crown/.ssh && chmod 700 /home/crown/.ssh && \
    chown crown:crown /home/crown/.ssh
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 2222
CMD ["/entrypoint.sh"]
