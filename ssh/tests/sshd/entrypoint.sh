#!/bin/sh
set -e
ssh-keygen -A
for bits in 384 521; do
  [ -f /etc/ssh/ssh_host_ecdsa${bits}_key ] ||     ssh-keygen -q -t ecdsa -b ${bits} -N '' -f /etc/ssh/ssh_host_ecdsa${bits}_key
done
exec /usr/sbin/sshd -D -e -p 2222
