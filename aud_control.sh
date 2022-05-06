#!/bin/bash -xe

build_aud_docker() {
    docker build -t aud_manager .
}

build_virtual_test_devices() {
    for vtd in virtual_test_devices/*/; do
        name=$(basename $vtd)
        #echo "here" $name
        docker build -t $name $vtd
    done
}

build_nflog_connector() {
    pushd aud_manager/data_intake_modules/nflog_connector
    make clean && make
    popd
}

start_nflog_connector() {

    if [ -z "$(pgrep nflog)" ]; then

        if [ ! -d "/tmp/aud" ]; then
            mkdir /tmp/aud
        fi

        sudo iptables -t filter -I DOCKER-USER -j NFLOG --nflog-group 7 --nflog-threshold 10
        sudo aud_manager/data_intake_modules/nflog_connector/nflog > /dev/null &
    fi

}

start_network() {
    docker network create --subnet=172.18.10.0/24 sifis_net
}

start_dockers() {
    docker run -d \
           --cap-add NET_ADMIN \
           --net sifis_net \
           --privileged \
           --ip 172.18.10.2 \
           --publish 5000:5000 \
           --mount type=bind,source="/tmp/aud",target="/tmp/aud" \
           --name aud_manager aud_manager

    ip_suffix=100

    for vtd in virtual_test_devices/*/; do
        name=$(basename $vtd)
        ((ip_suffix=$ip_suffix+1))

        docker run -d \
               --cap-add NET_ADMIN \
               --net sifis_net \
               --privileged \
               --ip 172.18.10.$ip_suffix \
               --name $name $name

    done
}

stop_dockers() {
    docker rm -f aud_manager || true

    for vtd in virtual_test_devices/*/; do
        name=$(basename $vtd)
        docker rm -f $name || true
    done
}

stop_network() {
    docker network rm sifis_net || true
}

stop_nflog_connector() {

    pid=$(pgrep nflog)

    if [ -n "$pid" ]; then
        sudo kill -9 $pid || true
        #rm -f /tmp/nflog_conn.pid
    fi
    sudo rm -rf /tmp/aud
    sudo iptables -t filter -D DOCKER-USER -j NFLOG --nflog-group 7 --nflog-threshold 10 || true
}


case "$1" in
    build)
        build_aud_docker
        build_virtual_test_devices
        build_nflog_connector
        ;;

    start)
        $0 build
        start_nflog_connector
        start_network
        start_dockers
        ;;

    restart)
        $0 stop
        $0 start
        ;;

    stop)
        stop_dockers
        stop_network
        stop_nflog_connector
        ;;

    clean)
        $0 stop
        docker system prune -a
        ;;

    *)
        exit 1
        ;;
esac
