FROM alpine:3.19

RUN apk add --no-cache coreutils util-linux

RUN printf '#!/bin/sh\n\
set -e\n\
echo "=== Runway Seccomp Demo ==="\n\
echo ""\n\
echo "[1] uname -a"\n\
uname -a\n\
echo ""\n\
echo "[2] id"\n\
id\n\
echo ""\n\
echo "[3] ls /"\n\
ls /\n\
echo ""\n\
echo "[4] cat /etc/os-release"\n\
cat /etc/os-release\n\
echo ""\n\
echo "[5] getpid (via /proc/self/status)"\n\
head -n 6 /proc/self/status\n\
echo ""\n\
echo "=== All checks passed ==="\n' > /entrypoint.sh && chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
