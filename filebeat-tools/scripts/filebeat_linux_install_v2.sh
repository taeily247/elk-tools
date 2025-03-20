#!/bin/bash
Color_Off="\033[0m"
Red="\033[0;31m"
Green="\033[0;32m"

DIR_PATH=$(pwd)

function check_cmd() {
    _CMD=$1
    if ! command -v ${_CMD} >/dev/null 2>&1; then
        Logging "WARR" "Command [ ${_cmd} ] not found. \n"
        return 1
    else
        return 0
    fi
}

function run_cmd() {
    _CMD=$@
    printf "%s | %-*s | %s\n" "${_LOG_TIME}" 4 "CMD" "$@"
    eval "${_CMD}" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        printf "%s | %-*s | %s\n" "${_LOG_TIME}" 4 "OK" "command ok."
        return 0
    else
        printf "%s | %-*s | %s\n" "${_LOG_TIME}" 4 "FAIL" "command fail."
        return 1
    fi
}

function help_usage() {
    cat <<EOF
Usage: $0 [Options]
Options:
-i, --install             : Install filebeat
-r, --remove              : Remove filebeat
-v, --ver  [  INT   ]     : Version filebeat
EOF
    exit 0
}

function set_opts() {
    arguments=$(getopt --options v:hir \
    --longoptions ver:,help,install,remove \
    --name $(basename $0) \
    -- "$@")

    eval set -- "${arguments}"
    while true; do
        case "$1" in
            -i | --install  ) MODE="install"; shift   ;;
            -r | --remove   ) MODE="remove" ; shift   ;;
            -v | --ver      ) VERSION=$2    ; shift 2 ;;
            -h | --help     ) help_usage              ;;
            --              ) shift         ; break   ;;
            ?               ) help_usage              ;;
        esac
    done
    ### 남아 있는 인자를 얻기 위해 shift 한다.
    shift $((OPTIND-1))
}

function download_pkg() {
    run_cmd "curl -s \"http://elk.enter-citech.toastmaker.net/beat/ep-filebeat-${VERSION}-linux-x86_64.tar.gz\" >${DIR_PATH}/ep-filebeat-${VERSION}-linux-x86_64.tar.gz"
    if [ $? -eq 0 ]; then
        run_cmd "tar -zxf ${DIR_PATH}/ep-filebeat-${VERSION}-linux-x86_64.tar.gz -C /usr/local/."
        run_cmd "chown -R root.root /usr/local/filebeat-${VERSION}"
        if [ $? -eq 0 ]; then
            run_cmd "rm -f ${DIR_PATH}/ep-filebeat-${VERSION}-linux-x86_64.tar.gz"
        fi
    fi
}

function setup_service() {
    check_cmd "systemctl"
    if [ $? -eq 0 ]; then
        run_cmd "cp -fp /usr/local/filebeat-${VERSION}/filebeat.service.systemd /usr/lib/systemd/system/filebeat.service"
        run_cmd "systemctl daemon-reload"
        run_cmd "systemctl start filebeat"
    else
        check_cmd "service"
        if [ $? -eq 0 ]; then
            run_cmd "cp -fp /usr/local/filebeat-${VERSION}/filebeat.service.initd /etc/init.d/filebeat"
            run_cmd "chmod +x /etc/init.d/filebeat"
            run_cmd "chkconfig --level35 filebeat on"
            run_cmd "service filebeat start"
        fi
    fi
}

function remove_service() {
    if pidof filebeat 2>&1 >/dev/null; then
        check_cmd "service"
        if [ $? -eq 0 ]; then
            run_cmd "service filebeat stop"
            run_cmd "chkconfig --level35 filebeat off"
            run_cmd "rm -f /etc/init.d/filebeat"
            run_cmd "rm -rf /usr/local/filebeat-${VERSION}"
        else
            check_cmd "systemctl"
            if [ $? -eq 0 ]; then
                run_cmd "systemctl stop filebeat"
                run_cmd "systemctl disable filebeat"
                run_cmd "rm -f /usr/lib/systemd/system/filebeat.service"
                run_cmd "systemctl daemon-reload"
                run_cmd "rm -rf /usr/local/filebeat-${VERSION}"
            fi
        fi
    fi
}

main() {
    [ $# -eq 0 ] && help_usage
    set_opts "$@"

    case ${MODE} in
        "install" )
            download_pkg
            setup_service
        ;;
        "remove"  )
            remove_service
        ;;
        *         ) help_usage     ; exit 0 ;;
    esac
}
main $*