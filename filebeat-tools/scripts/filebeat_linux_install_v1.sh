#!/bin/bash
### Colorset
# Reset
ResetCl='\033[0m'       # Text Reset

# Bold
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BBlack='\033[1;37m'       # White
BBlack='\033[1;38m'       # Black
BCyan='\033[1;36m'        # Cyan

install_url='http://pkg-server/filebeat/linux'
filebeat_ver="filebeat-7.17.16"
base_path='/etc/filebeat'

function run_cmd() {
    eval "$1" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

function check_os() {
    case `uname` in
        Linux )
            if [ $(which yum) ]; then
                _install_arr=("rpm" "x86_64.rpm")
            elif [ $(which apt-get) ]; then
                _install_arr=("dpkg" "amd64.deb")
            fi
        ;;
        * )
            printf "${BRed}no supported os${ResetCl}\n"
            exit 0
        ;;
    esac
    echo "${_install_arr[@]}"
}

function install_pkg() {
    install=(`check_os`)
    install_type="${install[0]}"
    install_pkg="${filebeat_ver}-${install[1]}"

    case ${install_type} in
        rpm )
            if [ `rpm -qa |grep -q filebeat |echo $?` ]; then
                printf "${BBlack}[1] Download pkg [ ${install_pkg} ] => "
                run_cmd "curl -sLO ${install_url}/pkgs/${install_pkg}"
                if [ $? -eq 0 ]; then
                    printf "${BGreen}OK${ResetCl}\n"
                    install_cmd=("rpm -ivh ${install_pkg}")
                else
                    printf "${BRed}Fail${ResetCl}\n"
                    exit 0
                fi
            else
                printf "${BRed}Already installed filebeat!\n"
                printf "Please check filebeat.${ResetCl}\n"
                exit 0
            fi
        ;;
        dpkg )
            if [ `dpkg --get-selections |grep -v deinstall |grep -q filebeat |echo $?` ]; then
                printf "${BBlack}[1] Download pkg [ ${install_pkg} ] => "
                run_cmd "curl -sLO ${install_url}/pkgs/${install_pkg}"
                if [ $? -eq 0 ]; then
                    printf "${BGreen}OK${ResetCl}\n"
                    install_cmd=("dpkg -Bi ${install_pkg}")
                else
                    printf "${BRed}Fail${ResetCl}\n"
                    exit 0
                fi
            else
                printf "${BRed}Already installed filebeat!\n"
                printf "Please check filebeat.${ResetCl}\n"
                exit 0
            fi
        ;;
    esac

    printf "${BBlack}[2] Install pkg [ ${install_pkg} ] => "
    run_cmd "${install_cmd}"
    if [ $? -eq 0 ]; then
        printf "${BGreen}OK${ResetCl}\n"
        printf "${BBlack}[3] Config setup [ filebeat.yml ]\n\n"
        run_cmd "mv ${base_path}/filebeat.yml ${base_path}/filebeat.yml.org"
        run_cmd "curl -sLO $install_url/conf/filebeat.yml"
        run_cmd "mv ./filebeat.yml ${base_path}/filebeat.yml"
        return 0
    else
        return 1
    fi
}

main() {
    printf "${BBlack}========================="
    printf "   Install filebeat for ELK. "
    printf "=========================${ResetCl}\n\n"

    install_pkg
    if [ $? -ne 0 ]; then
        run_cmd "rm -f ${install_pkg}"
        printf "${BRed}Install fail${ResetCl}\n"
        exit 0
    else
        printf "${BGreen}Install ok.${ResetCl}\n"

        printf "${BBlack}=========================\n"
        printf "1.Add host info to /etc/hosts file.\n"
        printf "192.168.1.1 elk\n\n"

        command -v systemctl |grep -q systemctl
        if [ $? -eq 0  ]; then
            printf "2. Excute command your system.\n"
            printf "Run command: [ ${BCyan}systemctl start filebeat && systemctl enable --now filebeat${ResetCl} ]\n"
            printf "${BBlack}=========================${ResetCl}\n"
        elif [ $? -eq 1 ]; then
            printf "2. Excute command type your system.\n"
            printf "Run command: [ ${BCyan}service filebeat start${ResetCl} ]\n"
            printf "${BBlack}Run command: [ ${BCyan}chkconfig filebeat on${ResetCl} ]\n\n"
        fi
    fi
}
main $*
# curl -s http://pkg-server/filebeat/linux/bootstrap.sh | bash