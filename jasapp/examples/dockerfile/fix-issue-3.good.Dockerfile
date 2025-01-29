FROM alpine:3.20 AS previous

RUN touch /test.txt

FROM debian:bookworm

# here false positive STX0020 because of --from=previous 
COPY --from=previous /test.txt /root/test.txt

USER nobody

HEALTHCHECK CMD stat /bin/bash