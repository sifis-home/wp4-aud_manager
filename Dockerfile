FROM --platform=$BUILDPLATFORM alpine:3.11

RUN apk --no-cache update   && \
    apk upgrade             && \
    apk add python3
RUN pip3 install flask

ARG TARGETPLATFORM
ARG COMMIT_ID

COPY aud_manager /home/aud_manager

RUN echo "$COMMIT_ID" > /home/aud_manager/COMMIT_ID

EXPOSE 6060/tcp

WORKDIR /home/aud_manager
ENTRYPOINT ["/usr/bin/python3", "/home/aud_manager/aud_manager.py"]
