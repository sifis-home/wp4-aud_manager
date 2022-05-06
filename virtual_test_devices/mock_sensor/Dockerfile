FROM alpine:3.4

RUN apk --no-cache update && \
    apk add curl

COPY mock.sh /home/.

ENTRYPOINT ["/home/mock.sh"]
