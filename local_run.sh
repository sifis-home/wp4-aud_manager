#!/bin/bash -xe

target="aud_sensor"

docker_build() {
    docker build -t "$target" -f Dockerfile --load .
}

docker_run() {
    sudo docker run -it --network host "$target"
}


sudo -v

case "$1" in
    docker)
        docker_build
        docker_run
        ;;
    *)
        exit 1
        ;;
esac
