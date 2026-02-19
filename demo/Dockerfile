FROM alpine:3.19

RUN apk add --no-cache coreutils util-linux curl

# Demo entrypoint: run a series of syscall-exercising commands
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
