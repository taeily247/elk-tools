# elk-tools
ELK Stack 관련 tools 및 문서

### 업데이트 내역
- 25.08 update v0.1 : ELK 설치 스크립트 및 테스트 환경 아키텍쳐 첨부

### 참고
- Elasticsearch
<br>elasticsearch 관련 커널 추천 값 #1: [링크](https://www.gimsesu.me/elasticsearch-change-vm-max-map-count/)
<br>elasticsearch 관련 커널 추천 값 #2: [링크](https://trace90.tistory.com/entry/ElasticSearch-%EB%A6%AC%EB%88%85%EC%8A%A4-OS-%ED%99%98%EA%B2%BD%EC%84%A4%EC%A0%95)
<br>elasticsearch config 설정[Single Cluster] : [링크](https://daram.tistory.com/548)

## 설치 방법
### install_elk.sh
Usage: ./install_elk.sh [Options]<br>
Options:<br>
-i, --install  [ NAME ]    : Install ELK<br>
-r, --remove   [ NAME ]    : Remove  ELK<br>
-u, --user     [ STRING ]  : ELK User (deafult: app)<br>
-s, --svr      [ STRING ]  : ELK Service name (deafult: ${ELK_SVR})<br>
-c, --cluster  [ STRING ]  : ES Cluster name  (deafult: ${ES_CLUSTER})<br>
-p, --path     [ STRING ]  : ELK Path (deafult: /DATA)<br>
-v, --ver      [   INT  ]  : ELK Version (deafult: 9.0.3)<br>
--cores        [   INT  ]  : Logstash core counts  (deafult: ${ELK_MAX_CORE})<br>
--min-mem      [ INT Gb ]  : JVM Heap Minimum size (default: ${ELK_MEM_MIN}g)<br>
--max-mem      [ INT Gb ]  : JVM Heap Maximum size (default: ${ELK_MEM_MAX}g)<br>

> Elasticsearch를 설치하는 경우

Exmaple: ./install_elk.sh -i elasticsearch -u app -s elk.taeily247.com -p /DATA -v 9.0.3

1. Data Path 경로 생성
2. 요청한 서비스의 바이너리 파일 다운로드, 링크 설정
3. linux 커널 값 설정
4. 서비스 유저의 Quota값
5. Data path내 필요한 디렉토리 생성 및 기본 Config 설정
6. 서비스 기동 스크립트 생성
7. 생성된 디렉토리 내 서비스유저 권한으로 변경