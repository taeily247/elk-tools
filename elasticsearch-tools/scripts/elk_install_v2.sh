dnf -y install java-17-openjdk
dnf -y install perl-Digest-SHA
[root@elk pkgs]# java --version
openjdk 17.0.9 2023-10-17 LTS
OpenJDK Runtime Environment (Red_Hat-17.0.9.0.9-1) (build 17.0.9+9-LTS)
OpenJDK 64-Bit Server VM (Red_Hat-17.0.9.0.9-1) (build 17.0.9+9-LTS, mixed mode, sharing)

export ELK_PATH="${HOME}/TOOLS/ELK_STACK"
mkdir -p ${ELK_PATH}/pkgs && cd ${ELK_PATH}/pkgs

wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.1-x86_64.rpm -P ${ELK_PATH}/pkgs
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.1-x86_64.rpm.sha512 -P ${ELK_PATH}/pkgs
shasum -a 512 -c elasticsearch-8.11.1-x86_64.rpm.sha512 

wget https://artifacts.elastic.co/downloads/logstash/logstash-8.11.1-x86_64.rpm -P ${ELK_PATH}/pkgs 
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.11.1-x86_64.rpm.sha512 -P ${ELK_PATH}/pkgs
shasum -a 512 -c logstash-8.11.1-x86_64.rpm.sha512

wget https://artifacts.elastic.co/downloads/kibana/kibana-8.11.1-x86_64.rpm -P ${ELK_PATH}/pkgs
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.11.1-x86_64.rpm.sha512 -P ${ELK_PATH}/pkgs
shasum -a 512 -c kibana-8.11.1-x86_64.rpm.sha512

sudo rpm -ivh ${ELK_PATH}/pkgs/*.rpm

for service in elasticsearch logstash kibana; do
    systemctl stop ${service}
done

cp -p /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.org
sed -i '/^#network.host:/a\network.host: 0.0.0.0' /etc/elasticsearch/elasticsearch.yml
sed -i 's/^#http.port: 9200/http.port: 9200/g' /etc/elasticsearch/elasticsearch.yml
#sed -i 's/^cluster.initial_master_nodes: [ "$(hostname)" ]/#&\ncluster.initial_master_nodes: [ "elk" ]/g' /etc/elasticsearch/elasticsearch.yml

cp -p /etc/sysconfig/elasticsearch /etc/sysconfig/elasticsearch.org
sed -i '/^#ES_JAVA_OPTS=/a\ES_JAVA_OPTS="-Djava.net.preferIPv4Stack=true"' /etc/sysconfig/elasticsearch

firewall-cmd --permanent --add-port=9200/tcp
firewall-cmd --permanent --add-port=9300/tcp
firewall-cmd --reload


### basic ssl auth
/usr/share/elasticsearch/bin/elasticsearch-certutil ca --days 365
[root@elk ssl]# /usr/share/elasticsearch/bin/elasticsearch-certutil ca --days 365
This tool assists you in the generation of X.509 certificates and certificate
signing requests for use with SSL/TLS in the Elastic stack.

The 'ca' mode generates a new 'certificate authority'
This will create a new X.509 certificate and private key that can be used
to sign certificate when running in 'cert' mode.

Use the 'ca-dn' option if you wish to configure the 'distinguished name'
of the certificate authority

By default the 'ca' mode produces a single PKCS#12 output file which holds:
    * The CA certificate
    * The CA's private key

If you elect to generate PEM format certificates (the -pem option), then the output will
be a zip file containing individual files for the CA certificate and private key


Please enter the desired output file [elastic-stack-ca.p12]: 
Enter password for elastic-stack-ca.p12 :
'
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12
#elasticsearch-certutil cert --silent --in config/instances.yml --out certs.zip --ca elastic-stack-ca.p12 --days 730
[root@elk ssl]# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12
This tool assists you in the generation of X.509 certificates and certificate
signing requests for use with SSL/TLS in the Elastic stack.

The 'cert' mode generates X.509 certificate and private keys.
    * By default, this generates a single certificate and key for use
       on a single instance.
    * The '-multiple' option will prompt you to enter details for multiple
       instances and will generate a certificate and key for each one
    * The '-in' option allows for the certificate generation to be automated by describing
       the details of each instance in a YAML file

    * An instance is any piece of the Elastic Stack that requires an SSL certificate.
      Depending on your configuration, Elasticsearch, Logstash, Kibana, and Beats
      may all require a certificate and private key.
    * The minimum required value for each instance is a name. This can simply be the
      hostname, which will be used as the Common Name of the certificate. A full
      distinguished name may also be used.
    * A filename value may be required for each instance. This is necessary when the
      name would result in an invalid file or directory name. The name provided here
      is used as the directory name (within the zip) and the prefix for the key and
      certificate files. The filename is required if you are prompted and the name
      is not displayed in the prompt.
    * IP addresses and DNS names are optional. Multiple values can be specified as a
      comma separated string. If no IP addresses or DNS names are provided, you may
      disable hostname verification in your SSL configuration.


    * All certificates generated by this tool will be signed by a certificate authority (CA)
      unless the --self-signed command line option is specified.
      The tool can automatically generate a new CA for you, or you can provide your own with
      the --ca or --ca-cert command line options.


By default the 'cert' mode produces a single PKCS#12 output file which holds:
    * The instance certificate
    * The private key for the instance certificate
    * The CA certificate

If you specify any of the following options:
    * -pem (PEM formatted output)
    * -multiple (generate multiple certificates)
    * -in (generate certificates from an input file)
then the output will be be a zip file containing individual certificate/key files

Enter password for CA (elastic-stack-ca.p12) :
Please enter the desired output file [elastic-certificates.p12]:
Enter password for elastic-certificates.p12 :

Certificates written to /usr/share/elasticsearch/elastic-certificates.p12

This file should be properly secured as it contains the private key for
your instance.
This file is a self contained file and can be copied and used 'as is'
For each Elastic product that you wish to configure, you should copy
this '.p12' file to the relevant configuration directory
and then follow the SSL configuration instructions in the product guide.

For client applications, you may only need to copy the CA certificate and
configure the client to trust this certificate.

cp -p /usr/share/elasticsearch/*.p12 /etc/elasticsearch/certs/.
sed -i 's/  keystore.path: certs\/transport.p12/#&\n  keystore.path: certs\/elastic-certificates.p12/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/  truststore.path: certs\/transport.p12/#&\n  truststore.path: certs\/elastic-certificates.p12/g' /etc/elasticsearch/elasticsearch.yml



systemctl restart elasticsearch && systemctl enable --now elasticsearch
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i --url https://elk:9200


cat <<EOF >/etc/elasticsearch/certs/elk-server.yml
instances:
  - name: 'elk-server'
    dns: [ 'elk-server' ]
  - name: 'kibana'
    dns: [ 'elk-server' ]
  - name: 'logstash'
    dns: [ 'elk-server' ]
EOF
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --keep-ca-key --pem --in /etc/elasticsearch/certs/elk-server.yml --out /etc/elasticsearch/certs/.



/usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent \
--days 365 \
--ca /etc/elasticsearch/certs/elk-server.ca \
--in /etc/elasticsearch/certs/elk-server.yml \
--out /etc/elasticsearch/certs/elk_certs.tar.gz


[root@elk certs]# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent \
> --days 365 \
> --ca /etc/elasticsearch/certs/elk-server.ca \
> --in /etc/elasticsearch/certs/elk-server.yml \
> --out /etc/elasticsearch/certs/elk_certs.zip
Enter password for CA (/etc/elasticsearch/certs/elk-server.ca) :
Enter password for elk-server/elk-server.p12 :
Enter password for kibana/kibana.p12 :
Enter password for logstash/logstash.p12 :
[root@elk certs]# ls
elk-server.ca  elk-server.yml  elk_certs.tar.gz  org

[root@elk certs]# unzip -d elk_certs elk_certs.zip
Archive:  elk_certs.zip
   creating: elk_certs/elk-server/
  inflating: elk_certs/elk-server/elk-server.p12
   creating: elk_certs/kibana/
  inflating: elk_certs/kibana/kibana.p12
   creating: elk_certs/logstash/
  inflating: elk_certs/logstash/logstash.p12

sed -i 's/  keystore.path: certs\/http.p12/#&\n  keystore.path: certs\/elk_certs\/elk-server\/elk-server.p12/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/  keystore.path: certs\/transport.p12/#&\n  keystore.path: certs\/elk_certs\/elk-server\/elk-server.p12/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/  truststore.path: certs\/transport.p12/#&\n  truststore.path: certs\/elk_certs\/elk-server\/elk-server.p12/g' /etc/elasticsearch/elasticsearch.yml

/usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password
/usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password
/usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password
/usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.http.ssl.truststore.secure_password

[root@elk-server elasticsearch]# /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password
Setting xpack.security.transport.ssl.keystore.secure_password already exists. Overwrite? [y/N]Y
Enter value for xpack.security.transport.ssl.keystore.secure_password:
[root@elk-server elasticsearch]# /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password
Setting xpack.security.transport.ssl.truststore.secure_password already exists. Overwrite? [y/N]Y
Enter value for xpack.security.transport.ssl.truststore.secure_password:
[root@elk-server elasticsearch]# /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password
Setting xpack.security.http.ssl.keystore.secure_password already exists. Overwrite? [y/N]Y
Enter value for xpack.security.http.ssl.keystore.secure_password:
[root@elk-server elasticsearch]# /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.http.ssl.truststore.secure_password
Setting xpack.security.http.ssl.truststore.secure_password already exists. Overwrite? [y/N]Y
Enter value for xpack.security.http.ssl.truststore.secure_password:

/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i --url https://elk-server:9200

[root@elk-server ~]# /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i --url https://elk-server:9200
This tool will reset the password of the [elastic] user.
You will be prompted to enter the password.
Please confirm that you would like to continue [y/N]Y


Enter password for [elastic]:
Re-enter password for [elastic]:
Password for the [elastic] user successfully reset.



curl -u elastic --cacert /etc/elasticsearch/certs/http_ca.crt https://elk-server:9200
GfGU9B73*g3YDFim11v1
[root@elk ssl]# curl -u elastic:GfGU9B73*g3YDFim11v1 --cacert /etc/elasticsearch/certs/http_ca.crt https://localhost:9200
{
  "name" : "elk",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "ekYbQmobThGkTrj_P7A2Hw",
  "version" : {
    "number" : "8.11.1",
    "build_flavor" : "default",
    "build_type" : "rpm",
    "build_hash" : "6f9ff581fbcde658e6f69d6ce03050f060d1fd0c",
    "build_date" : "2023-11-11T10:05:59.421038163Z",
    "build_snapshot" : false,
    "lucene_version" : "9.8.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}


### doc url https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html#network-interface-values
### doc url https://stackoverflow.com/questions/58236799/configuring-elastic-search-to-listen-on-0-0-0-09200-ipv4

cp -p /etc/kibana/kibana.yml /etc/kibana/kibana.yml.org
sed -i '/^#server.port: 5601/a\server.port: 5601' /etc/kibana/kibana.yml
sed -i /^#server.host: "localhost"/a\server.host: "elk-server"' /etc/kibana/kibana.yml
sed -i '/^#elasticsearch.hosts: ["http:\/\/localhost:9200"]/a\elasticsearch.hosts: ["https:\/\/elk:9200"]' /etc/kibana/kibana.yml
sed -i '/^#elasticsearch.username: "kibana_system"/a\elasticsearch.username: "elastic"' /etc/kibana/kibana.yml
sed -i '/^#elasticsearch.password: "pass"/a\elasticsearch.password: "ry123@"' /etc/kibana/kibana.yml
sed -i '/^#server.ssl.enabled: false/a\server.ssl.enabled: true' /etc/kibana/kibana.yml
sed -i '/^#server.ssl.certificate:/a\server.ssl.certificate: \/etc\/elasticsearch\/certs\/elk\/elk.crt' /etc/kibana/kibana.yml
sed -i '/^#server.ssl.key:/a\server.ssl.key: \/etc\/elasticsearch\/certs\/elk\/elk.key' /etc/kibana/kibana.yml
sed -i '/^#elasticsearch.ssl.certificate:/a\elasticsearch.ssl.certificate: \/etc\/elasticsearch\/certs\/elk\/elk.crt' /etc/kibana/kibana.yml
sed -i '/^#elasticsearch.ssl.key:/a\elasticsearch.ssl.key: \/etc\/elasticsearch\/certs\/elk\/elk.key' /etc/kibana/kibana.yml
sed -i '/^#elasticsearch.ssl.certificateAuthorities/a\elasticsearch.ssl.certificateAuthorities: [ "\/etc\/elasticsearch\/certs/ca\/ca.crt" ]' /etc/kibana/kibana.yml