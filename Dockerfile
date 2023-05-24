FROM --platform=$BUILDPLATFORM alpine:3.11

RUN apk --no-cache update   && \
    apk upgrade             && \
    apk add python3
RUN pip3 install flask

ARG TARGETPLATFORM
ARG COMMIT_ID

COPY aud_sensor /home/aud_sensor

RUN echo "$COMMIT_ID" > /home/aud_sensor/COMMIT_ID

EXPOSE 6060/tcp

WORKDIR /home/aud_sensor
ENTRYPOINT ["/usr/bin/python3", "/home/aud_sensor/aud_sensor.py"]
