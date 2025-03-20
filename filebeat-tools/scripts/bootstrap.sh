#!/bin/bash
Color_Off="\033[0m"
Red="\033[0;31m"
Green="\033[0;32m"

function run_cmd() {
    _CMD=$@
    MSG_FORMAT "CMD" "$@"
    eval "${_CMD}" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        MSG_FORMAT "OK" "Command OK."
        return 0
    else
        MSG_FORMAT "FAIL" "Command Fail."
        return 1
    fi
}

function MSG_FORMAT() {
    _TYPE=$1
    _MSG=$2
    case ${_TYPE} in
        ERROR ) printf "[ ${Red}%-*s${Color_Off} ] %s\n" 4 "${_TYPE}" "${_MSG}"   ;;
        OK    ) printf "[ ${Green}%-*s${Color_Off} ] %s\n" 4 "${_TYPE}" "${_MSG}" ;;
    esac
}

function main() {
    OS_TYPE=$1
    VERSION=$2

    if [ -z ${OS_TYPE} ]; then
        printf "ERROR" "Do not input argument. (Ex. linux or window )"
        exit 1
    fi

    case ${OS_TYPE} in
        linux|Linux|LINUX )
            run_cmd "curl -s \"http://pkg-server/beat/linux_install_filebeat.sh\" |bash -s -- -i -v \"${VERSION}\""
        ;;
        window|Window|WINDOW|windows|Windows|WINDOWS )
            run_cmd "curl -s \"http://pkg-server/beat/window_install_filebeat.sh\" |bash -s -- -i -v \"${VERSION}\""
        ;;
    esac
}
main $*