FROM alpine:3.11

RUN apk --no-cache update   && \
    apk upgrade             && \
    apk add python3
RUN pip3 install flask ipwhois

COPY aud_manager /home/aud_manager

VOLUME /tmp/aud
EXPOSE 5000/tcp

WORKDIR /home/aud_manager
ENTRYPOINT ["/usr/bin/python3", "/home/aud_manager/aud_manager.py"]
