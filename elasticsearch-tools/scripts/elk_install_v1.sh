#!/bin/bash
cat <<EOF >>/etc/hosts

192.168.1.1 elk
EOF

firewall-cmd --permanent --add-port={443/tcp,9200/tcp,5601/tcp,5044/tcp}
firewall-cmd --reload

sed -i 's/SELINUX=enforcing/#&\nSELINUX=disabled/g' /etc/selinux/config

export ELK_PATH="${HOME}/TOOLS/elk"
mkdir -p ${ELK_PATH}/pkgs

## 1. JVM install 
dnf list java*jdk-devel
# [root@localhost ~]# dnf list java*jdk-devel
# 마지막 메타자료 만료확인(0:55:26 이전): 2023년 12월 10일 (일) 오전 09시 11분 36초.
# 사용 가능한 꾸러미
# java-1.8.0-openjdk-devel.x86_64                   1:1.8.0.392.b08-4.el8_8                    appstream
# java-11-openjdk-devel.x86_64                      1:11.0.21.0.9-2.el8_8                      appstream
# java-17-openjdk-devel.x86_64                      1:17.0.9.0.9-2.el8_8                       appstream
# java-21-openjdk-devel.x86_64                      1:21.0.1.0.12-3.el8                        appstream
dnf install -y java-17-openjdk-devel

## 2. Elasticsearch
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.2-x86_64.rpm -P ${ELK_PATH}/pkgs
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.2-x86_64.rpm.sha512 -P ${ELK_PATH}/pkgs
cd ${ELK_PATH}/pkgs
sha512sum -c elasticsearch-8.11.2-x86_64.rpm.sha512 && rpm --install elasticsearch-8.11.2-x86_64.rpm
# ## 결과 예시
# --------------------------- Security autoconfiguration information ------------------------------

# Authentication and authorization are enabled.
# TLS for the transport and HTTP layers is enabled and configured.

# The generated password for the elastic built-in superuser is : *BK*lO1ljgzsteV*LZff

# If this node should join an existing cluster, you can reconfigure this with
# '/usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token <token-here>'
# after creating an enrollment token on your existing cluster.

# You can complete the following actions at any time:

# Reset the password of the elastic built-in superuser with
# '/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic'.

# Generate an enrollment token for Kibana instances with
#  '/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana'.

# Generate an enrollment token for Elasticsearch nodes with
# '/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node'.

# -------------------------------------------------------------------------------------------------
# ### NOT starting on installation, please execute the following statements to configure elasticsearch service to start automatically using systemd
#  sudo systemctl daemon-reload
#  sudo systemctl enable elasticsearch.service
# ### You can start elasticsearch service by executing
#  sudo systemctl start elasticsearch.service


## 2-1. [ Elastic ] 설정
cp -p /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.org
sed -i '/#network.host: 192.168.0.1/a\network.host: 0.0.0.0' /etc/elasticsearch/elasticsearch.yml
# sed -i 's/cluster.initial_master_nodes: \["localhost.localdomain"\]/#&\ncluster.initial_master_nodes: \["elk"\]/g' /etc/elasticsearch/elasticsearch.yml

# cp -p /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.org
# cat <<EOF >/etc/elasticsearch/jvm.options

# -Xms1g
# -Xmx1g
# -Djava.net.preferIPv4Stack=true
# EOF

## 2-2. [ Elastic ] 서비스 시작
systemctl start elasticsearch && systemctl enable --now elasticsearch

## 2-3. [ Elastic ] Kibana Token 생성
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic --interactive

### 결과 예시
# [root@localhost pkgs]# /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic --interactive
# This tool will reset the password of the [elastic] user.
# You will be prompted to enter the password.
# Please confirm that you would like to continue [y/N]y

# Enter password for [elastic]:
# Re-enter password for [elastic]:
# Password for the [elastic] user successfully reset.

/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
### 결과 예시
# [root@localhost pkgs]# /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
# eyJ2ZXIiOiI4LjExLjIiLCJhZHIiOlsiMTAuMjExLjU1LjEwOjkyMDAiXSwiZmdyIjoiZWE0NmFkZjg1YTE2MWRlZjA4Y2NkYmVlOTE0NDExNmY2NGFlMTFlMTZiODU4ZGNlNDg2ODg4NGFkYWM3MmU5ZiIsImtleSI6IndMR0RWSXdCOWJ2UXBnZmlSc1Q1OmYxUklud2Y2U2otc3FEZUZIWDhBRFEifQ==

## 2-3 서비스 확인
curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic:'ep!123' https://localhost:9200?\pretty
### 결과 예시
# [root@localhost pkgs]# curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic:'ep!123' https://localhost:9200?\pretty
# {
#   "name" : "localhost.localdomain",
#   "cluster_name" : "elasticsearch",
#   "cluster_uuid" : "R_6hK9IbS463Ywps5qIY7Q",
#   "version" : {
#     "number" : "8.11.2",
#     "build_flavor" : "default",
#     "build_type" : "rpm",
#     "build_hash" : "76013fa76dcbf144c886990c6290715f5dc2ae20",
#     "build_date" : "2023-12-05T10:03:47.729926671Z",
#     "build_snapshot" : false,
#     "lucene_version" : "9.8.0",
#     "minimum_wire_compatibility_version" : "7.17.0",
#     "minimum_index_compatibility_version" : "7.0.0"
#   },
#   "tagline" : "You Know, for Search"
# }

## 3. Kibana
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.11.2-x86_64.rpm -P ${ELK_PATH}/pkgs
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.11.2-x86_64.rpm.sha512 -P ${ELK_PATH}/pkgs
cd ${ELK_PATH}/pkgs
sha512sum -c kibana-8.11.2-x86_64.rpm.sha512 && rpm --install kibana-8.11.2-x86_64.rpm

## 3-1. 설정
cp -p /etc/kibana/kibana.yml /etc/kibana/kibana.yml.org
sed -i '/#server.host: "localhost"/a\server.host: "elk"' /etc/kibana/kibana.yml
sed -i '/#elasticsearch.hosts: \["http:\/\/localhost:9200"\]/a\elasticsearch.hosts: \["https:\/\/elk:9200"\]' /etc/kibana/kibana.yml
sed -i '/# elasticsearch.serviceAccountToken: "my_token"/a\elasticsearch.serviceAccountToken: "eyJ2ZXIiOiI4LjExLjIiLCJhZHIiOlsiMTAuMjExLjU1LjEwOjkyMDAiXSwiZmdyIjoiZWE0NmFkZjg1YTE2MWRlZjA4Y2NkYmVlOTE0NDExNmY2NGFlMTFlMTZiODU4ZGNlNDg2ODg4NGFkYWM3MmU5ZiIsImtleSI6IndMR0RWSXdCOWJ2UXBnZmlSc1Q1OmYxUklud2Y2U2otc3FEZUZIWDhBRFEifQ=="' /etc/kibana/kibana.yml

## 3-2. 서비스 기동
systemctl start kibana && systemctl enable --now kibana

## 3-3. 서비스 확인
http://192.168.1.1:5601

## 4. logstash
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.11.2-x86_64.rpm -P ${ELK_PATH}/pkgs
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.11.2-x86_64.rpm.sha512 -P ${ELK_PATH}/pkgs
cd ${ELK_PATH}/pkgs
sha512sum -c logstash-8.11.2-x86_64.rpm.sha512 && rpm --install logstash-8.11.2-x86_64.rpm
systemctl start logstash && systemctl enable --now logstash

## 5. Filebeat
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.2-linux-x86_64.tar.gz -P ${ELK_PATH}/pkgs
tar -zxf ${ELK_PATH}/pkgs/filebeat-8.11.2-linux-x86_64.tar.gz  -C ${ELK_PATH}













###
### 결과 오류 예시
# [2023-12-10T10:55:40,965][WARN ][o.e.c.c.ClusterFormationFailureHelper] [localhost.localdomain] master not discovered yet, this node has not previously joined a bootstrapped cluster, and this node must discover master-eligible nodes [elk] to bootstrap a cluster: have discovered [{localhost.localdomain}{eF0Gl2y1R42BcpfYXaBjSA}{EB7HavjKSYqXGWp532Drxg}{localhost.localdomain}{192.168.1.1}{192.168.1.1:9300}{cdfhilmrstw}{8.11.2}{7000099-8500003}]; discovery will continue using [127.0.0.1:9300, 127.0.0.1:9301, 127.0.0.1:9302, 127.0.0.1:9303, 127.0.0.1:9304, 127.0.0.1:9305] from hosts providers and [{localhost.localdomain}{eF0Gl2y1R42BcpfYXaBjSA}{EB7HavjKSYqXGWp532Drxg}{localhost.localdomain}{192.168.1.1}{192.168.1.1:9300}{cdfhilmrstw}{8.11.2}{7000099-8500003}] from last-known cluster state; node term 0, last-accepted version 0 in term 0; for troubleshooting guidance, see https://www.elastic.co/guide/en/elasticsearch/reference/8.11/discovery-troubleshooting.html
# [2023-12-10T10:55:47,441][WARN ][r.suppressed             ] [localhost.localdomain] path: /_cluster/health, params: {pretty=}
# org.elasticsearch.discovery.MasterNotDiscoveredException: null
# 	at org.elasticsearch.action.support.master.TransportMasterNodeAction$AsyncSingleAction$2.onTimeout(TransportMasterNodeAction.java:317) ~[elasticsearch-8.11.2.jar:?]
# 	at org.elasticsearch.cluster.ClusterStateObserver$ContextPreservingListener.onTimeout(ClusterStateObserver.java:355) ~[elasticsearch-8.11.2.jar:?]
# 	at org.elasticsearch.cluster.ClusterStateObserver$ObserverClusterStateListener.onTimeout(ClusterStateObserver.java:293) ~[elasticsearch-8.11.2.jar:?]
# 	at org.elasticsearch.cluster.service.ClusterApplierService$NotifyTimeout.run(ClusterApplierService.java:645) ~[elasticsearch-8.11.2.jar:?]
# 	at org.elasticsearch.common.util.concurrent.ThreadContext$ContextPreservingRunnable.run(ThreadContext.java:916) ~[elasticsearch-8.11.2.jar:?]
# 	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144) ~[?:?]
# 	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642) ~[?:?]
# 	at java.lang.Thread.run(Thread.java:1583) ~[?:?]
# ...
# [2023-12-10T10:58:09,747][WARN ][o.e.d.PeerFinder         ] [localhost.localdomain] address [127.0.0.1:9301], node [null], requesting [false] discovery result: [][127.0.0.1:9301] connect_exception: Failed execution: io.netty.channel.AbstractChannel$AnnotatedConnectException: Connection refused: /127.0.0.1:9301: Connection refused: /127.0.0.1:9301: Connection refused
# [2023-12-10T10:58:09,747][WARN ][o.e.d.PeerFinder         ] [localhost.localdomain] address [127.0.0.1:9302], node [null], requesting [false] discovery result: [][127.0.0.1:9302] connect_exception: Failed execution: io.netty.channel.AbstractChannel$AnnotatedConnectException: Connection refused: /127.0.0.1:9302: Connection refused: /127.0.0.1:9302: Connection refused
# [2023-12-10T10:58:09,748][WARN ][o.e.d.PeerFinder         ] [localhost.localdomain] address [127.0.0.1:9303], node [null], requesting [false] discovery result: [][127.0.0.1:9303] connect_exception: Failed execution: io.netty.channel.AbstractChannel$AnnotatedConnectException: Connection refused: /127.0.0.1:9303: Connection refused: /127.0.0.1:9303: Connection refused
# [2023-12-10T10:58:09,748][WARN ][o.e.d.PeerFinder         ] [localhost.localdomain] address [127.0.0.1:9305], node [null], requesting [false] discovery result: [][127.0.0.1:9305] connect_exception: Failed execution: io.netty.channel.AbstractChannel$AnnotatedConnectException: Connection refused: /127.0.0.1:9305: Connection refused: /127.0.0.1:9305: Connection refused
# = Cluster init 설정이 잘못되었을 경우 연동실패로 인한 에러, 해당 옵션을 주석 처리 혹은 host 정보를 확인 후 재기동