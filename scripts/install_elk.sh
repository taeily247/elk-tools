#!/bin/bash

##### Enviroment - Common
ELK_PATH="/DATA"
PKGS=()

##### Enviroment - Kernel
KERNEL_PARAMETER=(
    'vm.max_map_count = 524288'
    'vm.swappiness = 1'
)
##### Enviroment - ELK
ELK_VER="9.0.3"
ELK_USER="app"
ELK_USER_HOME="$(eval echo ~${ELK_USER})"
ELK_SVR="elk-test.com"
ELK_NODENAME="$(hostname)"

ELK_MAX_CORE=$(grep -c 'core id' /proc/cpuinfo)
ELK_MEM_MIN=$(awk '/MemTotal/ {printf "%.0f\n", (($2/1024/1024)*90)/100}' /proc/meminfo)
ELK_MEM_MAX=$(awk '/MemTotal/ {printf "%.0f\n", (($2/1024/1024)*90)/100}' /proc/meminfo)

##### Enviroment - ES
ES_CLUSTER="elastic-test.com"

function checkCommand() {
    # shasum = perl-Digest-SHA
    _command=('shasum')
    for i in ${_command[@]}; do
        command -v ${i} >/dev/null
        [ $? -eq 1 ] && { logging "ERROR" "Command not found [ ${i} ]"; exit 1; }
    done
}

function runCommand() {
    _command=$@
    logging "CMD" "$@"
    eval "${_command}" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        logging "OK"
        return 0
    else
        logging "FAIL"
        return 1
    fi
}

function logging() {
    _log_command="tee -a ${SCRIPT_LOG}/script_$(date +%y%m%d).log"

    _timestamp=$(date "+%y%m%d %H:%M:%S.%3N")
    _type=$1
    _msg=$2

    case ${_type} in
        "OK"    ) printf "%s\n" "Command OK"   ;;
        "FAIL"  ) printf "%s\n" "Command FAIL" ;;
        "CMD"   ) printf "%s | %-*s | %s => " "${_timestamp}" 7 "${_type}" "${_msg}"     ;;
        "INFO"  ) printf "%s | %-*s | %s\n" "${_timestamp}" 7 "${_type}" "${_msg}"       ;;
        "WARR"  ) printf "%s | %-*s | %s\n" "${_timestamp}" 7 "${_type}" "${_msg}"       ;;
        "SKIP"  ) printf "%s | %-*s | %s\n" "${_timestamp}" 7 "${_type}" "${_msg}"       ;;
        "ERROR" ) printf "%s | %-*s | %s\n" "${_timestamp}" 7 "${_type}" "${_msg}"       ;;
        # "CMD"   ) printf "%s | %-*s | %s\n" "${_timestamp}" 7 "${_type}" "${_msg}"   |tee -a ${LOG_FILE} >/dev/null ;;
    esac
}

function help() {
    cat <<EOF
Usage: $0 [Options]
Options:
-i, --install  [ NAME ]    : Install ELK
-r, --remove   [ NAME ]    : Remove  ELK
-u, --user     [ STRING ]  : ELK User (deafult: ${ELK_USER})
-s, --svr      [ STRING ]  : ELK Service name (deafult: ${ELK_SVR})
-c, --cluster  [ STRING ]  : ES Cluster name  (deafult: ${ES_CLUSTER})
-p, --path     [ STRING ]  : ELK Path (deafult: ${ELK_PATH})
-v, --ver      [   INT  ]  : ELK Version (deafult: ${ELK_VER})
--cores        [   INT  ]  : Logstash core counts  (deafult: ${ELK_MAX_CORE})
--min-mem      [ INT Gb ]  : JVM Heap Minimum size (default: ${ELK_MEM_MIN}g)
--max-mem      [ INT Gb ]  : JVM Heap Maximum size (default: ${ELK_MAX_MIN}g)
EOF
    exit 0
}

function setOptions() {
    arguments=$(getopt --options u:s:c:p:v:i:r:h \
    --longoptions user:,svr:,cluser:,path:,ver:,core:,min-mem:,max-mem:,install:,remove:,help \
    --name $(basename $0) \
    -- "$@")

    eval set -- "${arguments}"
    while true; do
        # echo "[DEBUG] parsing option: $1"
        case "$1" in
            # -i | --install ) MODE="install"; PKGS=($2); shift 2 ;;
            -i | --install )
                MODE="install"
                # 1. 첫 번째 인자(예: test1,test2 or test1) 처리
                IFS=',' read -ra _tmp_pkgs <<<"$2"
                PKGS=("${_tmp_pkgs[@]}")
                shift 2

                # 2. 남은 인자 중에서 옵션(--xxxx) 아닌 것들을 계속 추가
                while [[ $# -gt 0 && "$1" != -* && "$1" != --* ]]; do
                    PKGS+=("$1")
                    shift
                done
            ;;
            -r | --remove   ) MODE="remove"; PKGS=($2); shift 2 ;;
            -u | --user     ) ELK_USER=$2   ; shift 2 ;;
            -s | --svr      ) ELK_SVR=$2    ; shift 2 ;;
            -c | --cluster  ) ES_SVR=$2     ; shift 2 ;;
            -p | --path     ) ELK_PATH=$2   ; shift 2 ;;
            -v | --ver      ) ELK_VER=$2    ; shift 2 ;;
            --core          ) ELK_MAX_CORE=$2   ; shift 2 ;;
            --min-mem       ) ELK_MEM_MIN=$2    ; shift 2 ;;
            --max-mem       ) ELK_MEM_MAX=$2    ; shift 2 ;;
            -h | --help     ) help                    ;;
            --              ) shift         ; break   ;;
            ?               ) logging "ERROR" "Unknown option: $1"; exit 1 ;;
        esac
    done
    # shift $((OPTIND-1))
}

function instPackages() {
    _pkgs=("$@")
    for i in ${_pkgs[@]}; do
        if [ -d ${ELK_PATH}/${i}-${ELK_VER} ]; then
            logging "SKIP" "Already install ${ELK_PATH}/${i}-${ELK_VER}"
            continue
        fi

        runCommand "curl -s https://artifacts.elastic.co/downloads/${i}/${i}-${ELK_VER}-linux-x86_64.tar.gz -o ${ELK_PATH}/pkgs/${i}-${ELK_VER}-linux-x86_64.tar.gz"
        runCommand "curl -s https://artifacts.elastic.co/downloads/${i}/${i}-${ELK_VER}-linux-x86_64.tar.gz.sha512 -o ${ELK_PATH}/pkgs/${i}-${ELK_VER}-linux-x86_64.tar.gz.sha512"
        
        runCommand "cd ${ELK_PATH}/pkgs"
        runCommand "shasum -a 512 -qc ${i}-${ELK_VER}-linux-x86_64.tar.gz.sha512"
        [ $? -eq 1 ] && { logging "ERROR" "fail donwload ${i}-${ELK_VER}"; return 1; }

        runCommand "tar -zxf ${i}-${ELK_VER}-linux-x86_64.tar.gz -C ${ELK_PATH}/."
        runCommand "cd ${ELK_PATH}"

        if [ -f ${ELK_PATH}/${i} ]; then
            logging "WARR" "Already ${ELK_PATH}/${i}, so Change new [ ${i}-${ELK_VER} ]"
            runCommand "ln -Tfs ${i}-${ELK_VER} ${i}"
        else
            runCommand "ln -s ${i}-${ELK_VER} ${i}"
            [ $? -eq 0 ] && logging "INFO" "Install completed ${i}"
        fi
    done
}

function setPackages() {
    _pkg="$1"

    case ${_pkg} in
        "elasticsearch" )
            setupElasticsearch
        ;;
        "logstash" )
            setupLogstash
        ;;
        "kibana" ) 
            setupKibana
        ;;
    esac
}

function setupElasticsearch() {
    for i in "${KERNEL_PARAMETER[@]}"; do
        ## rv = Request Value, cv = Current Value
        key=$(echo "${i}" |awk -F' = ' '{print $1}')
        rv=$(echo "${i}" |awk -F' = ' '{print $NF}')
        cv=$(sysctl ${key} |awk -F'= ' '{print $NF}')

        [ -f /etc/sysctl.d/elastic_sysctl.conf ] && runCommand "sysctl -p /etc/sysctl.d/elastic_sysctl.conf"
        [ ${rv} -eq ${cv} ] && logging "SKIP" "Already setup sysctl config [ ${i} ]"
        if ! $(grep -q ${key} /etc/sysctl.conf); then
            if ! $(grep -q ${key} /etc/sysctl.d/*); then
                runCommand "touch /etc/sysctl.d/elastic_sysctl.conf"
                runCommand "echo '${i}' >>/etc/sysctl.d/elastic_sysctl.conf"
                runCommand "sysctl -p /etc/sysctl.d/elastic_sysctl.conf"

                cv=$(sysctl ${key} |awk -F'= ' '{print $NF}')
                [ ${rv} -eq ${cv} ] && logging "INFO" "Setup sysctl config file [ ${i} ]"
            fi
        else
            [ ${rv} -eq ${cv} ] && logging "INFO" "Already Setup sysctl config file [ ${i} ]"
        fi
    done

    if [ ! -f /etc/security/limits.d/${ELK_USER}.conf ]; then
        runCommand "
cat <<EOF >/etc/security/limits.d/${ELK_USER}.conf
${ELK_USER}       soft    nofile         65536
${ELK_USER}       hard    nofile         65536
${ELK_USER}       soft    nproc          65536
${ELK_USER}       hard    nproc          65536
${ELK_USER}       soft    memlock        unlimited
${ELK_USER}       hard    memlock        unlimited
EOF
"
        [ $? -eq 1 ] && { logging "ERROR" "fail create file security limits. [ /etc/security/limits.d/${ELK_USER}.conf ]"; return 1; }
    else
        logging "SKIP" "Already create file security limits."
    fi

    [ ! -d ${ELK_PATH}/elasticsearch/data ] && runCommand "mkdir ${ELK_PATH}/elasticsearch/data"
    
    if ! $(grep -q "${ELK_PATH}/elasticsearch/data" ${ELK_PATH}/elasticsearch/config/elasticsearch.yml ); then
        runCommand "cat <<EOF >${ELK_PATH}/elasticsearch/config/elasticsearch.yml
path.data: ${ELK_PATH}/elasticsearch/data
path.logs: ${ELK_PATH}/elasticsearch/logs
bootstrap.memory_lock: true

# eth0 인터페이스에 설정된 ip4를 사용하여 데이터 전송
network.host: _eth0:ipv4_
network.bind_host: [ _local_, _global_ ]
http.port: 9200
transport.port: 9300

cluster.name: ${ELK_SVR}
cluster.initial_master_nodes: [ \"${ELK_NODENAME}\" ]
discovery.seed_hosts: [ \"${ELK_NODENAME}\" ]

node.name: ${ELK_NODENAME}
node.roles: [ master, data, ingest, ml]

### ES Disable SSL
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
EOF"
    else
        logging "SKIP" "Already setup ${ELK_PATH}/elasticsearch/config/elasticsearch.yml"
    fi

    if ! $(grep -q "^-Xms${ELK_MEM_MIN}" ${ELK_PATH}/elasticsearch/config/jvm.options); then
        runCommand "cat <<EOF >>${ELK_PATH}/elasticsearch/config/jvm.options

-Xmx${ELK_MEM_MIN}g
-Xms${ELK_MEM_MAX}g
EOF"
    else
        logging "SKIP" "Already setup ${ELK_PATH}/elasticsearch/config/jvm.options"
    fi

    if [ ! -f ${ELK_PATH}/scripts/service_elastic.sh ]; then
        runCommand "cat <<EOF >${ELK_PATH}/scripts/service_elastic.sh
#!/bin/bash
MODE=\\\$1
ES_PATH=\"${ELK_PATH}/elasticsearch\"
ES_PROC=\"\\\${ES_PATH}/bin/elasticsearch\"
ES_PID=\"\\\${ES_PATH}/data/elastic.pid\"

case \"\\\${MODE}\" in
\"start\" )
    if [ -e \\\${ES_PID} ]; then
        _pid=\\\$(cat \\\${ES_PID})
        echo \"Start up failed, please check if ElasticSearch (PID: \\\${_pid}) is running.\"
        exit 0
    else
        echo \"\\\${ES_PROC} -d -p \\\${ES_PID} &\"
        \\\${ES_PROC} -d -p \\\${ES_PID} &
    fi
;;
\"stop\" )
    if [ -e \\\${ES_PID} ]; then
        _pid=\\\$(cat \\\${ES_PID})
        kill \\\${_pid}
        while ps -p \\\${_pid} >/dev/null; do sleep 1; done
        [ -f \\\${ES_PID} ] && rm -f \\\${ES_PID}
        echo \"ElasticSearch successfully stopped.\"
    else
        echo \"Stop Failed, please check if ElasticSearch was already stopped.\"
        exit 0
    fi
;;
\"restart\" )
    if [ -e \\\${ES_PID} ]; then
        _pid=\\\$(cat \\\${ES_PID})
        kill \\\${_pid}
        while ps -p \\\${_pid} >/dev/null; do sleep 1; done
        [ -f \\\${ES_PID} ] && rm -f \\\${ES_PID}
        if [ ! -f \\\${ES_PID} ]; then
            echo \"Elasticsearch successfully stopped. and so restart Elasticsearch\"
            echo \"\\\${ES_PROC} -d -p \\\${ES_PID} &\"
            \\\${ES_PROC} -d -p \\\${ES_PID} &
        fi
    fi
;;
* )
    echo \"Undefined cmd\"
    exit 0
;;
esac
EOF"
        if [ $? -eq 0 ]; then
            runCommand "chmod +x ${ELK_PATH}/scripts/service_elastic.sh"
            logging "INFO" "Succes create elastic sevice script [ ${ELK_PATH}/scripts/service_elastic.sh ]"
        else
                logging "ERROR" "Fail create elastic sevice script [ ${ELK_PATH}/scripts/service_elastic.sh ]"
                return 1
        fi
    else
        logging "SKIP" "Already create elastic sevice script [ ${ELK_PATH}/scripts/service_elastic.sh ]"
        return 0
    fi
}

setupKibana() {
    [ ! -d ${ELK_PATH}/kibana/data ] && runCommand "mkdir ${ELK_PATH}/kibana/data"
    
    if ! $(grep -q "${ELK_PATH}/kibana/data" ${ELK_PATH}/kibana/config/kibana.yml ); then
        runCommand "cat <<EOF >/${ELK_PATH}/kibana/config/kibana.yml
server.name: ${ELK_SVR}
server.host: 0.0.0.0
server.port: 5601
server.publicBaseUrl: \"http://${ELK_SVR}:5601\"

path.data: ${ELK_PATH}/kibana/data
pid.file: ${ELK_PATH}/kibana/data/kibana.pid

logging.root.level: info
logging.appenders.default:
    type: file
    fileName: ${ELK_PATH}/kibana/logs/kibana.log
    layout:
        type: json

elasticsearch.url: \"http://${ES_CLUSTER}:9200\"
EOF"
    else
        logging "SKIP" "Already setup ${ELK_PATH}/kibana/config/kibana.yml"
    fi

    if [ ! -f ${ELK_PATH}/scripts/service_kibana.sh ]; then
        runCommand "cat <<EOF >${ELK_PATH}/scripts/service_kibana.sh
#!/bin/bash
MODE=\\\$1
KIBANA_PATH=\"${ELK_PATH}/kibana\"
KIBANA_PROC=\"\\\${KIBANA_PATH}/bin/kibana\"
KIBANA_PID=\"\\\${KIBANA_PATH}/data/kibana.pid\"

case \"\\\${MODE}\" in
\"start\" )
    if [ -e \\\${KIBANA_PID} ]; then
        _pid=\\\$(cat \\\${KIBANA_PID})
        echo \"Start up failed, please check if Kibana (PID: \\\${_pid}) is running.\"
        exit 0
    else
        echo \"\\\${KIBANA_PROC} &\"
        \\\${KIBANA_PROC} &
    fi
;;
\"stop\" )
    if [ -e \\\${KIBANA_PID} ]; then
        _pid=\\\$(cat \\\${KIBANA_PID})
        kill \\\${_pid}
        while ps -p \\\${_pid} >/dev/null; do sleep 1; done
        [ -f \\\${KIBANA_PID} ] && rm -f \\\${KIBANA_PID}
        echo \"Kibana successfully stopped.\"
    else
        echo \"Stop Failed, please check if Kibana was already stopped.\"
        exit 0
    fi
;;
\"restart\" )
    if [ -e \\\${KIBANA_PID} ]; then
        _pid=\\\$(cat \\\${KIBANA_PID})
        kill \\\${_pid}
        while ps -p \\\${_pid} >/dev/null; do sleep 1; done
        [ -f \\\${KIBANA_PID} ] && rm -f \\\${KIBANA_PID}
        if [ ! -f \\\${KIBANA_PID} ]; then
            echo \"Kibana successfully stopped. and so restart Kibana\"
            echo \"\\\${KIBANA_PROC} &\"
            \\\${KIBANA_PROC} &
        fi
    else
        echo \"Restart Failed, please check if Kibana was already stopped.\"
        exit 0
    fi
;;
* )
    echo \"Undefined cmd\"
    exit 0
;;
esac
EOF"
        if [ $? -eq 0 ]; then
            runCommand "chmod +x ${ELK_PATH}/scripts/service_kibana.sh"
            logging "INFO" "Succes create elastic sevice script [ ${ELK_PATH}/scripts/service_kibana.sh ]"
        else
                logging "ERROR" "Fail create elastic sevice script [ ${ELK_PATH}/scripts/service_kibana.sh ]"
                return 1
        fi
    else
        logging "SKIP" "Already create elastic sevice script [ ${ELK_PATH}/scripts/service_kibana.sh ]"
        return 0
    fi
}

setupLogstash() {
    [ ! -d ${ELK_PATH}/logstash/conf.d ] && runCommand "mkdir ${ELK_PATH}/logstash/conf.d"
    
    if ! $(grep -q "${ELK_PATH}/logstash/data" ${ELK_PATH}/logstash/config/logstash.yml ); then
        runCommand "cat <<EOF >/${ELK_PATH}/logstash/config/logstash.yml
node.name: ${ELK_NODENAME}
path.config: ${ELK_PATH}/logstash/conf.d/*.conf
path.data: ${ELK_PATH}/logstash/data
path.logs: ${ELK_PATH}/logstash/logs
EOF"
    else
        logging "SKIP" "Already setup ${ELK_PATH}/logstash/config/logstash.yml"
    fi

    if ! $(grep -q "^-Xms${ELK_MEM_MIN}" ${ELK_PATH}/logstash/config/jvm.options); then
        runCommand "sed -i 's/^-Xmx/#&/g' ${ELK_PATH}/logstash/config/jvm.options"
        runCommand "sed -i '/^#-Xmx/a-Xmx${ELK_MEM_MAX}g' ${ELK_PATH}/logstash/config/jvm.options"
        runCommand "sed -i 's/^-Xms/#&/g' ${ELK_PATH}/logstash/config/jvm.options"
        runCommand "sed -i '/^#-Xms/a-Xms${ELK_MEM_MIN}g' ${ELK_PATH}/logstash/config/jvm.options"
    else
        logging "SKIP" "Already setup ${ELK_PATH}/logstash/config/jvm.options"
    fi

    if ! $(grep -q "^pipeline.workers: ${ELK_MAX_CORE}" ${ELK_PATH}/logstash/config/pipelines.yml); then
        runCommand "sed -i '\$a pipline.workers: ${ELK_MAX_CORE}' ${ELK_PATH}/logstash/config/pipelines.yml"
    else
        logging "SKIP" "Already setup ${ELK_PATH}/logstash/config/pipelines.yml"
    fi

    if ! $(grep -q "${ELK_PATH}/logstash" ${ELK_PATH}/logstash/config/startup.options); then
        runCommand "sed -i 's/^LS_HOME=/#&/g' ${ELK_PATH}/logstash/config/startup.options"
        runCommand "sed -i '/^#LS_HOME=/a\LS_HOME=${ELK_PATH}\/logstash' ${ELK_PATH}/logstash/config/startup.options"

        runCommand "sed -i 's/^LS_SETTINGS_DIR=/#&/g' ${ELK_PATH}/logstash/config/startup.options"
        runCommand "sed -i '/^#LS_SETTINGS_DIR=/a\LS_SETTINGS_DIR=${ELK_PATH}\/logstash\/config' ${ELK_PATH}/logstash/config/startup.options"

        runCommand "sed -i 's/^LS_PIDFILE=/#&/g' ${ELK_PATH}/logstash/config/startup.options"
        runCommand "sed -i '/^#LS_PIDFILE=/a\LS_PIDFILE=${ELK_PATH}\/logstash\/data\/logstash.pid' ${ELK_PATH}/logstash/config/startup.options"

        runCommand "sed -i 's/^LS_USER=/#&/g' ${ELK_PATH}/logstash/config/startup.options"
        runCommand "sed -i '/^#LS_USER=/a\LS_USER=${ELK_USER}' ${ELK_PATH}/logstash/config/startup.options"
        runCommand "sed -i 's/^LS_GROUP=/#&/g' ${ELK_PATH}/logstash/config/startup.options"
        runCommand "sed -i '/^#LS_GROUP=/a\LS_GROUP=${ELK_USER}' ${ELK_PATH}/logstash/config/startup.options"

        runCommand "sed -i 's/^LS_GC_LOG_FILE=/#&/g' ${ELK_PATH}/logstash/config/startup.options"
        runCommand "sed -i '/^#LS_GC_LOG_FILE=/a\LS_GC_LOG_FILE=${ELK_PATH}/logstash/logs/gc.log' ${ELK_PATH}/logstash/config/startup.options"
    else
        logging "SKIP" "Already setting ${ELK_PATH}/logsasth/config/startip.options"
    fi

    if [ ! -f ${ELK_PATH}/scripts/service_logstash.sh ]; then
        runCommand "cat <<EOF >${ELK_PATH}/scripts/service_logstash.sh
#!/bin/bash
MODE=\\\$1
LOGSTASH_PATH=\"${ELK_PATH}/logstash\"
LOGSTASH_PROC=\"\\\${LOGSTASH_PATH}/bin/logstash\"
LOGSTASH_PID=\"\\\${LOGSTASH_PATH}/data/logstash.pid\"

case \"\\\${MODE}\" in
\"start\" )
    if [ -e \\\${LOGSTASH_PID} ]; then
        _pid=\\\$(cat \\\${LOGSTASH_PID})
        echo \"Start up failed, please check if Logstash (PID: \\\${_pid}) is running.\"
        exit 0
    else
        echo \"\\\${LOGSTASH_PROC} & echo \\\$! >\\\${LOGSTASH_PID}\"
        \\\${LOGSTASH_PROC} & echo \\\$! >\\\${LOGSTASH_PID}
    fi
;;
\"stop\" )
    if [ -e \\\${LOGSTASH_PID} ]; then
        _pid=\\\$(cat \\\${LOGSTASH_PID})
        kill \\\${_pid}
        while ps -p \\\${_pid} >/dev/null; do sleep 1; done
        [ \$? -eq 0 ] && rm -f \\\${LOGSTASH_PID}
        echo \"Logstash successfully stopped.\"
    else
        echo \"Stop Failed, please check if Logstash was already stopped.\"
        exit 0
    fi
;;
\"restart\" )
    if [ -e \\\${LOGSTASH_PID} ]; then
        _pid=\\\$(cat \\\${LOGSTASH_PID})
        kill \\\${_pid}
        while ps -p \\\${_pid} >/dev/null; do sleep 1; done
        [ \$? -eq 0 ] && rm -f \\\${LOGSTASH_PID}
        if [ ! -f ${LOGSTASH_PID} ]; then
            echo \"Logstash successfully stopped. and so restart Logstash\"
            echo \"\\\${LOGSTASH_PROC} & echo \\\$! >\\\${LOGSTASH_PID}\"
            \\\${LOGSTASH_PROC} & echo \\\$! >\\\${LOGSTASH_PID}
        fi
        echo \"Stop Failed, please check if Logstash was already stopped.\"
        exit 0
    fi
;;
* )
    echo \"Undefined cmd\"
    exit 0
;;
esac
EOF"
        if [ $? -eq 0 ]; then
            runCommand "chmod +x ${ELK_PATH}/scripts/service_logstash.sh"
            logging "INFO" "Succes create elastic sevice script [ ${ELK_PATH}/scripts/service_logstash.sh ]"
        else
                logging "ERROR" "Fail create elastic sevice script [ ${ELK_PATH}/scripts/service_logstash.sh ]"
                return 1
        fi
    else
        logging "SKIP" "Already create elastic sevice script [ ${ELK_PATH}/scripts/service_logstash.sh ]"
        return 0
    fi

    if [ ! -f ${ELK_PATH}/logstash/conf.d/input.conf ]; then
        runCommand "cat <<EOF >${ELK_PATH}/logstash/conf.d/input.conf
input {
    beats {
        port => \"5044\"
    }
}
EOF"
    else
        logging "SKIP" "Already create pipeline file [ ${ELK_PATH}/logstash/conf.d/input.conf ]"
    fi
    
    if [ ! -f ${ELK_PATH}/logstash/conf.d/filter.conf ]; then
        runCommand "cat <<EOF >${ELK_PATH}/logstash/conf.d/filter.conf
filter {
    if [type] == \"secure\" {
        grok {
            patterns_dir   => [ \"${ELK_PATH}/logstash/conf.d/grok_pattern\" ]
            match          => { \"message\" => \"%{SYSLOGTIMESTAMP} %{GREEDYDATA:message}\" }
            overwrite => [ \"message\" ]
        }
    }
    date {
        match  => [ \"timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ]
        target => \"@timestamp\"
    }

}
EOF"
    else
        logging "SKIP" "Already create pipeline file [ ${ELK_PATH}/logstash/conf.d/filter.conf ]"
    fi

    if [ ! -f ${ELK_PATH}/logstash/conf.d/output.conf ]; then
        runCommand "cat <<EOF >${ELK_PATH}/logstash/conf.d/output.conf
output {
    elasticsearch {
        index       => \"%{[host][hostname]}-secure\"
        hosts       => \"${ELK_SVR}:9200\"
    }
}
EOF"
    else
        logging "SKIP" "Already create pipeline file [ ${ELK_PATH}/logstash/conf.d/output.conf ]"
    fi
}

main() {
    [ $# -eq 0 ] && help
    setOptions "$@"
    checkCommand

    if [ ! -d ${DATA_PATH} ]; then
        runCommand "mkdir -p ${DATA_PATH}/pkgs"
        [ $? -eq 1 ] && { logging "ERROR" "fail create directory ${DATA_PATH}"; exit 1; }
    fi
    
    case ${MODE} in
        "install" )
            [ ! -d ${ELK_PATH}/pkgs ] && runCommand "mkdir -p ${ELK_PATH}/{pkgs,scripts}"
            
            _delete_idx=()
            for ((i=0; i<${#PKGS[@]}; i++)); do
                case ${PKGS[$i]} in
                    "all" ) PKGS=("elasticsearch" "logstash" "kibana") ; break ;;
                    "elasticsearch"|"logstash"|"kibana" ) continue ;;
                    * )
                        logging "WARR" "Not supported install packages names [ ${PKGS[$i]} ]"
                        _delete_idx+=(${i})
                    ;;
                esac
            done

            for i in ${_delete_idx[@]}; do
                unset 'PKGS[i]'
            done

            [ ${#PKGS[@]} -eq 0 ] && { logging "ERROR" "No install pkgs list."; exit 0; }

            instPackages "${PKGS[@]}"
            [ $? -eq 1 ] && exit 0

            for i in "${PKGS[@]}"; do
                setPackages "${i}"
                [ $? -eq 1 ] && { logging "ERROR" "Setup fail ${i}"; exit 0; }
                runCommand "chown -R ${ELK_USER} ${ELK_PATH}/*"
            done
        ;;
        "remove"  ) echo "remote"  ; exit 0 ;;
        *         ) help           ; exit 0 ;;
    esac
}
main $*