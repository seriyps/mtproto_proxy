#!/bin/sh
# Script that helps to overwrite port/secret/ad tag from command line without changing config-files

CMD="/opt/mtp_proxy/bin/mtp_proxy foreground"
THIS=$0

usage() {
    echo "Usage:"
    echo "To run with settings from config/prod-sys.config:"
    echo "${THIS}"
    echo "To start in single-port mode configured from command-line:"
    echo "${THIS} -p <port> -s <secret> -t <ad tag>"
}

error() {
    echo "ERROR: ${1}"
    usage
    exit 1
}

NUM_OPTS=0
PORT=""
SECRET=""
TAG=""

while getopts "p:s:t:h" o; do
    case "${o}" in
        p)
            PORT=${OPTARG}
            test ${PORT} -gt 0 -a ${PORT} -lt 65535 || error "Invalid port value: ${PORT}"
            ;;
        s)
            SECRET=${OPTARG}
            [ -n "`echo $SECRET | grep -x '[[:xdigit:]]\{32\}'`" ] || error "Invalid secret. Should be 32 chars of 0-9 a-f"
            ;;
        t)
            TAG=${OPTARG}
            [ -n "`echo $TAG | grep -x '[[:xdigit:]]\{32\}'`" ] || error "Invalid tag. Should be 32 chars of 0-9 a-f"
            ;;
        h)
            usage
            exit 0
    esac
    NUM_OPTS=$((NUM_OPTS + 1))
done

if [ $NUM_OPTS -eq 0 ]; then
    exec $CMD
elif [ $NUM_OPTS -eq 3 ]; then
    exec $CMD -mtproto_proxy ports "[#{name => mtproto_proxy, port => $PORT, secret => <<\"$SECRET\">>, tag => <<\"$TAG\">>}]"
else
    error "Not enough options: -p '${PORT}' -s '${SECRET}' -t '${TAG}'"
fi
