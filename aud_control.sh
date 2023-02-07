#!/bin/bash -xe

build_aud_dockers() {
    for target in aud_manager aud_sensor; do
        docker build -t $target -f docker-files/Dockerfile-$target .
    done
}

build_vtd_dockers() {
    for vtd in virtual_test_devices/*/; do
        name=$(basename $vtd)
        docker build -t $name $vtd
    done
}

build_nflog_connector() {
    pushd modules/nflog_connector
    make clean && make
    popd
}

nflog_connector() {
    pid=$(pgrep nflog)

    if [ $1 = "start" ] && [ -z "$pid" ]; then
        sudo mkdir -p /tmp/aud
        sudo modules/nflog_connector/nflog > /dev/null &

    elif [ $1 = "stop" ] && [ -n "$pid" ]; then
        sudo kill -9 $pid || true
        sudo rm -rf /tmp/aud

    fi
}

nflog_iptables() {

    table="filter"
    chain_in="INPUT"
    chain_out="OUTPUT"

    if [ $1 = "add" ]; then
        sudo iptables -t $table -I $chain_in -j NFLOG --nflog-group 7 --nflog-prefix "0" --nflog-threshold 10
        sudo iptables -t $table -I $chain_out -j NFLOG --nflog-group 7 --nflog-prefix "1" --nflog-threshold 10

    elif [ $1 = "remove" ]; then
        sudo iptables -t $table -D $chain_in -j NFLOG --nflog-group 7 --nflog-prefix "0" --nflog-threshold 10 || true
        sudo iptables -t $table -D $chain_out -j NFLOG --nflog-group 7 --nflog-prefix "1" --nflog-threshold 10 || true

    fi
}

sifis_network() {
    if [ $1 = "start" ]; then
        docker network create --subnet=172.18.10.0/24 sifis_net
    elif [ $1 = "stop" ]; then
        docker network rm sifis_net || true
    fi
}

start_aud_sensor() {
    docker run -d \
           --cap-add NET_ADMIN \
           --net host \
           --privileged \
           --mount type=bind,source="/tmp/aud",target="/tmp/aud" \
           --name aud_sensor aud_sensor
}

start_aud_manager() {
    docker run -d \
           --cap-add NET_ADMIN \
           --net host \
           --privileged \
           --mount type=bind,source="/tmp/aud",target="/tmp/aud" \
           --name aud_manager aud_manager
}

start_vtd_dockers() {
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
    docker rm -f aud_sensor || true
    #docker rm -f aud_manager || true

    for vtd in virtual_test_devices/*/; do
        name=$(basename $vtd)
        docker rm -f $name || true
    done
}

case "$1" in
    build)
        build_aud_dockers
        #build_vtd_dockers
        build_nflog_connector
        ;;

    start)
        $0 build
        nflog_iptables add
        nflog_connector start
        #sifis_network start
        start_aud_sensor
        #start_vtd_dockers
        ;;

    stop)
        stop_dockers
        #sifis_network stop
        nflog_connector stop
        nflog_iptables remove
        ;;

    restart)
        $0 stop
        $0 start
        ;;

    iptables)
        nflog_iptables $2
        ;;

    clean)
        $0 stop
        docker system prune -a
        ;;

    *)
        exit 1
        ;;
esac
