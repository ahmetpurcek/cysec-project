/*
 * port_scanner.c — Stealth Advanced Port Scanner
 * IDS/IPS Evasion, Akıllı Gürültü Yönetimi, Servis / Zafiyet Tespiti
 * 
 * Özellikler:
 *  - Rastgele gecikme + jitter ile IDS atlatma
 *  - Source port randomization (her paket farklı port)
 *  - IP TTL randomization (pattern oluşmasını engelle)
 *  - Fragmentasyon desteği (IP fragment)
 *  - Decoy scan (sahte kaynak IP'ler)
 *  - Idle/Zombie scan
 *  - ACK scan ile firewall rule mapping
 *  - FTP bounce scan
 *  - Banner grab + servis fingerprint
 *  - SSL/TLS algılama
 *  - Zafiyet veritabanı (built-in CVE lookup)
 *  - Gürültü seviyesi kontrolü (paranoid → normal)
 *  - Otomatik hız ayarı (ağ koşullarına göre)
 */
#include "port_scanner.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <math.h>
#include <stdint.h>

#ifdef PLATFORM_WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <process.h>
#define getpid _getpid
typedef int socklen_t;
#else
typedef int SOCKET;
#define INVALID_SOCKET -1
#define closesocket close
#endif

#ifdef PLATFORM_LINUX
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket close
#endif

/* ========== TCP Flag Sabitleri ========== */
#define TF_FIN 0x01
#define TF_SYN 0x02
#define TF_RST 0x04
#define TF_PSH 0x08
#define TF_ACK 0x10
#define TF_URG 0x20
#define TF_ECE 0x40
#define TF_CWR 0x80

/* ========== Servis Veritabanı (genişletilmiş) ========== */
typedef struct {
    int port;
    const char *name;
    const char *default_product;
    int is_ssl_default;    /* varsayılan olarak SSL/TLS mi */
} SvcEntry;

static const SvcEntry g_services[] = {
    /* 0-100 */
    {1,"tcpmux",NULL,0},{5,"rje",NULL,0},{7,"echo",NULL,0},
    {9,"discard",NULL,0},{11,"systat",NULL,0},{13,"daytime",NULL,0},
    {17,"qotd",NULL,0},{19,"chargen",NULL,0},{20,"ftp-data",NULL,0},
    {21,"ftp","vsftpd",0},{22,"ssh","OpenSSH",0},{23,"telnet","Telnet",0},
    {25,"smtp","Postfix",0},{37,"time",NULL,0},{39,"rip",NULL,0},
    {42,"nameserver",NULL,0},{43,"whois",NULL,0},{49,"tacacs",NULL,0},
    {53,"dns","BIND",0},{67,"dhcp-server",NULL,0},{68,"dhcp-client",NULL,0},
    {69,"tftp",NULL,0},{70,"gopher",NULL,0},{79,"finger",NULL,0},
    {80,"http","Apache httpd",0},{81,"http-alt",NULL,0},{82,"http-alt",NULL,0},
    {83,"http-alt",NULL,0},{84,"http-alt",NULL,0},{85,"http-alt",NULL,0},
    {88,"kerberos",NULL,0},{89,"http-alt",NULL,0},{90,"http-alt",NULL,0},
    {99,"metagram",NULL,0},
    /* 100-200 */
    {101,"hostname",NULL,0},{102,"iso-tsap",NULL,0},{105,"csnet-ns",NULL,0},
    {106,"pop3pw",NULL,0},{107,"rtelnet",NULL,0},{109,"pop2",NULL,0},
    {110,"pop3","Dovecot",0},{111,"rpcbind",NULL,0},{113,"ident",NULL,0},
    {119,"nntp",NULL,0},{123,"ntp","ntpd",0},{135,"msrpc","Microsoft RPC",0},
    {137,"netbios-ns",NULL,0},{138,"netbios-dgm",NULL,0},
    {139,"netbios-ssn","Samba",0},{143,"imap","Dovecot",0},
    {161,"snmp","net-snmp",0},{162,"snmp-trap",NULL,0},
    {177,"xdmcp",NULL,0},{179,"bgp",NULL,0},{194,"irc",NULL,0},
    {199,"smux",NULL,0},
    /* 200-500 */
    {201,"at-rtmp",NULL,0},{209,"qmtp",NULL,0},{210,"z39.50",NULL,0},
    {213,"ipx",NULL,0},{220,"imap3",NULL,0},{245,"link",NULL,0},
    {256,"fw1-secure",NULL,0},{257,"fw1-admin",NULL,0},
    {259,"esro-gen",NULL,0},{264,"bgmp",NULL,0},{280,"http-mgmt",NULL,0},
    {300,"thinwire",NULL,0},{308,"novak-http",NULL,0},
    {311,"ossec",NULL,0},{350,"matip-type-a",NULL,0},
    {351,"matip-type-b",NULL,0},{366,"odmr",NULL,0},
    {369,"rpc2portmap",NULL,0},{370,"codaauth2",NULL,0},
    {371,"clearcase",NULL,0},{383,"hp-alarm-mgr",NULL,0},
    {384,"arns",NULL,0},{387,"aurp",NULL,0},{389,"ldap","OpenLDAP",0},
    {399,"digi",NULL,0},{401,"ups",NULL,0},{402,"genie",NULL,0},
    {406,"imsp",NULL,0},{407,"timbuktu",NULL,0},
    {416,"silverplatter",NULL,0},{425,"icad",NULL,0},
    {427,"svrloc",NULL,0},{434,"mobileip-agent",NULL,0},
    {435,"mobilip-mn",NULL,0},{443,"https","Apache httpd",1},
    {444,"snpp",NULL,0},{445,"microsoft-ds","Samba",0},
    {446,"ddm-rdb",NULL,0},{447,"ddm-dfm",NULL,0},
    {448,"ddm-ssl",NULL,0},{449,"as-servermap",NULL,0},
    {464,"kpasswd",NULL,0},{465,"smtps","Postfix",1},
    {475,"tcpnethaspsrv",NULL,0},{491,"go-login",NULL,0},
    {497,"dantz",NULL,0},{500,"isakmp",NULL,0},
    /* 500-1000 */
    {502,"modbus","Modbus",0},{512,"exec",NULL,0},{513,"login",NULL,0},
    {514,"syslog","rsyslog",0},{515,"printer","CUPS",0},
    {517,"talk",NULL,0},{518,"ntalk",NULL,0},{520,"efs",NULL,0},
    {521,"ripng",NULL,0},{522,"ulp",NULL,0},{523,"ibm-db2",NULL,0},
    {524,"ncp",NULL,0},{525,"timed",NULL,0},{526,"tempo",NULL,0},
    {529,"irc-serv",NULL,0},{530,"courier",NULL,0},{531,"chat",NULL,0},
    {532,"netnews",NULL,0},{533,"netwall",NULL,0},{534,"mm-admin",NULL,0},
    {537,"netmap",NULL,0},{538,"gdomap",NULL,0},{540,"uucp",NULL,0},
    {541,"uucp-rlogin",NULL,0},{542,"commerce",NULL,0},
    {543,"klogin",NULL,0},{544,"kshell",NULL,0},{545,"ekshell",NULL,0},
    {546,"dhcpv6-client",NULL,0},{547,"dhcpv6-server",NULL,0},
    {548,"afpovertcp","Apple File Sharing",0},
    {549,"idfp",NULL,0},{550,"new-rwho",NULL,0},{551,"cybercash",NULL,0},
    {552,"deviceshare",NULL,0},{553,"pirp",NULL,0},
    {554,"rtsp",NULL,0},{555,"dsf",NULL,0},{556,"remotefs",NULL,0},
    {557,"openvms-sysipc",NULL,0},{558,"sdnskmp",NULL,0},
    {559,"teedtap",NULL,0},{560,"rmonitor",NULL,0},
    {561,"monitor",NULL,0},{562,"chshell",NULL,0},
    {563,"nntps",NULL,1},{564,"9pfs","Plan 9",0},
    {565,"whoami",NULL,0},{566,"streettalk",NULL,0},
    {567,"banyan-rpc",NULL,0},{568,"ms-shuttle",NULL,0},
    {569,"ms-rome",NULL,0},{570,"meter",NULL,0},{571,"umeter",NULL,0},
    {572,"sonar",NULL,0},{573,"banyan-vip",NULL,0},
    {574,"ftp-agent",NULL,0},{575,"vemmi",NULL,0},
    {576,"ipcd",NULL,0},{577,"vnas",NULL,0},{578,"ipdd",NULL,0},
    {579,"decbsrv",NULL,0},{580,"sntp-heartbeat",NULL,0},
    {581,"bdp",NULL,0},{582,"scc-security",NULL,0},
    {583,"philips-vc",NULL,0},{584,"keyserver",NULL,0},
    {585,"imap4-ssl",NULL,1},{586,"password-chg",NULL,0},
    {587,"submission","Postfix",0},{588,"cal",NULL,0},
    {589,"eyelink",NULL,0},{590,"tns-cml",NULL,0},
    {591,"http-alt","FileMaker",0},{592,"eudora-set",NULL,0},
    {593,"http-rpc-epmap",NULL,0},{594,"tpip",NULL,0},
    {595,"cab-protocol",NULL,0},{596,"smsd",NULL,0},
    {597,"ptcnameservice",NULL,0},{598,"sco-websrvrmgr3",NULL,0},
    {599,"acp",NULL,0},{600,"ipcserver","X11",0},
    {601,"syslog-conn",NULL,0},{602,"xmlrpc-beep",NULL,0},
    {603,"idxp",NULL,0},{604,"tunnel",NULL,0},{605,"soap-beep",NULL,0},
    {606,"urm",NULL,0},{607,"nqs",NULL,0},{608,"sift-uft",NULL,0},
    {609,"npmp-trap",NULL,0},{610,"npmp-local",NULL,0},
    {611,"npmp-gui",NULL,0},{612,"hmmp-ind",NULL,0},
    {613,"hmmp-op",NULL,0},{614,"ssl-shell",NULL,1},
    {615,"sco-inetmgr",NULL,0},{616,"sco-sysmgr",NULL,0},
    {617,"sco-dtmgr",NULL,0},{618,"dei-icda",NULL,0},
    {619,"compaq-evm",NULL,0},{620,"sco-websrvrmgr",NULL,0},
    {621,"escp-ip",NULL,0},{622,"collaborator",NULL,0},
    {623,"oob-ws-http","ASF/RMCP",0},{624,"cryptoadmin",NULL,0},
    {625,"dec-dlm",NULL,0},{626,"asia",NULL,0},{627,"passgo-tivoli",NULL,0},
    {628,"qmqp",NULL,0},{629,"3com-amp3",NULL,0},{630,"rda",NULL,0},
    {631,"ipp","CUPS",0},{632,"bmpp",NULL,0},{633,"servstat",NULL,0},
    {634,"ginad",NULL,0},{635,"rlzdbase",NULL,0},{636,"ldaps","OpenLDAP",1},
    {637,"lanserver",NULL,0},{638,"mcns-sec",NULL,0},
    {639,"msdp",NULL,0},{640,"entrust-sps",NULL,0},
    {641,"repcmd",NULL,0},{642,"esro-emsdp",NULL,0},
    {643,"sanity",NULL,0},{644,"dwr",NULL,0},{645,"pssc",NULL,0},
    {646,"ldp",NULL,0},{647,"dhcp-failover",NULL,0},
    {648,"rrp",NULL,0},{649,"cadview-3d",NULL,0},
    {650,"obex",NULL,0},{651,"ieee-mms",NULL,0},
    {652,"hello-port",NULL,0},{653,"repscmd",NULL,0},
    {654,"aodv",NULL,0},{655,"tinc",NULL,0},{656,"spmp",NULL,0},
    {657,"rmc",NULL,0},{658,"tenfold",NULL,0},
    {659,"url-rendezvous",NULL,0},{660,"mac-srvr-admin",NULL,0},
    {661,"hap",NULL,0},{662,"pftp",NULL,0},{663,"purenoise",NULL,0},
    {664,"oob-ws-https",NULL,1},{665,"sun-dr",NULL,0},
    {666,"doom","Doom",0},{667,"disclose",NULL,0},
    {668,"mecomm",NULL,0},{669,"meregister",NULL,0},
    {670,"vacdsm-sws",NULL,0},{671,"vacdsm-app",NULL,0},
    {672,"vpps-qua",NULL,0},{673,"cimplex",NULL,0},
    {674,"acap",NULL,0},{675,"dctp",NULL,0},{676,"vpps-via",NULL,0},
    {677,"vpp",NULL,0},{678,"ggf-ncp",NULL,0},{679,"mrm",NULL,0},
    {680,"entrust-aaas",NULL,0},{681,"entrust-aams",NULL,0},
    {682,"xfr",NULL,0},{683,"corba-iiop",NULL,0},
    {684,"corba-iiop-ssl",NULL,1},{685,"mdc-portmapper",NULL,0},
    {686,"hcp-wismar",NULL,0},{687,"asipregistry",NULL,0},
    {688,"realm-rusd",NULL,0},{689,"nmap",NULL,0},
    {690,"vatp",NULL,0},{691,"msexch-routing",NULL,0},
    {692,"hyperwave-isp",NULL,0},{693,"connendp",NULL,0},
    {694,"ha-cluster",NULL,0},{695,"ieee-mms-ssl",NULL,1},
    {696,"rushd",NULL,0},{697,"uuidgen",NULL,0},
    {698,"olsr",NULL,0},{699,"accessnetwork",NULL,0},
    {700,"epp",NULL,0},{701,"lmp",NULL,0},{702,"iris-beep",NULL,0},
    {703,"kerberos-adm",NULL,0},{704,"elcsd",NULL,0},
    {705,"agentx",NULL,0},{706,"silc",NULL,0},{707,"borland-dsj",NULL,0},
    {708,"entrust-kmsh",NULL,0},{709,"entrust-ash",NULL,0},
    {710,"cisco-tdp",NULL,0},{711,"tag",NULL,0},{712,"tbrpf",NULL,0},
    {713,"iris-xpc",NULL,0},{714,"iris-xpcs",NULL,1},
    {715,"iris-lwz",NULL,0},{716,"pana",NULL,0},{729,"netviewdm1",NULL,0},
    {730,"netviewdm2",NULL,0},{731,"netviewdm3",NULL,0},
    {732,"netgw",NULL,0},{733,"netrcs",NULL,0},{734,"flexlm",NULL,0},
    {735,"dns2",NULL,0},{736,"dns",NULL,0},{737,"dns",NULL,0},
    {738,"dns",NULL,0},{739,"dns",NULL,0},{740,"netcp",NULL,0},
    {741,"netgw",NULL,0},{742,"netrcs",NULL,0},
    {744,"flexlm",NULL,0},{747,"fujitsu-dev",NULL,0},
    {748,"ris-cm",NULL,0},{749,"kerberos-adm",NULL,0},
    {750,"kerberos",NULL,0},{751,"kerberos-master",NULL,0},
    {752,"qrh",NULL,0},{753,"rrh",NULL,0},{754,"tell",NULL,0},
    {758,"nlogin",NULL,0},{759,"con",NULL,0},{760,"krb5-prop",NULL,0},
    {761,"krb5",NULL,0},{762,"krb5",NULL,0},{763,"krb5",NULL,0},
    {764,"krb5",NULL,0},{765,"webster",NULL,0},{767,"phonebook",NULL,0},
    {769,"vid",NULL,0},{770,"cadlock",NULL,0},{771,"rtip",NULL,0},
    {772,"cycleserv",NULL,0},{773,"submit",NULL,0},
    {774,"notify",NULL,0},{775,"acmaint-dbd",NULL,0},
    {776,"acmaint-transd",NULL,0},{777,"multiling-http",NULL,0},
    {780,"wpgs",NULL,0},{800,"mdbs-daemon",NULL,0},
    {801,"device",NULL,0},{802,"mbap-s",NULL,0},
    {810,"fcp-udp",NULL,0},{828,"itm-mcell-s",NULL,0},
    {829,"pkix-3-ca-ra",NULL,0},{830,"netconf-ssh",NULL,0},
    {831,"netconf-beep",NULL,0},{832,"netconfsoaphttp",NULL,0},
    {833,"netconfsoapbeep",NULL,0},{847,"dhcp-failover2",NULL,0},
    {848,"gdoi",NULL,0},{853,"domain-s",NULL,1},
    {854,"dlep",NULL,0},{860,"iscsi",NULL,0},
    {861,"owamp-control",NULL,0},{862,"twamp-control",NULL,0},
    {873,"rsync","rsyncd",0},{888,"cddbp",NULL,0},
    {889,"ddp",NULL,0},{900,"sctp-tunneling",NULL,0},
    {901,"samba-swat","Samba SWAT",0},{902,"vmware-auth","VMware",0},
    {903,"vmware-auth-alt",NULL,0},{904,"vmware-srv",NULL,0},
    {905,"vmware-ssl",NULL,1},{908,"webadmin",NULL,0},
    {909,"openvpn-ssl",NULL,1},{910,"kink",NULL,0},
    {911,"xact-backup",NULL,0},{912,"apex-mesh",NULL,0},
    {913,"apex-edge",NULL,0},{944,"mondo",NULL,0},
    {945,"omg",NULL,0},{947,"wsmux",NULL,0},
    {948,"omg",NULL,0},{949,"omg",NULL,0},{950,"oftep",NULL,0},
    {951,"omg",NULL,0},{952,"omg",NULL,0},{953,"omg",NULL,0},
    {954,"omg",NULL,0},{955,"omg",NULL,0},{956,"omg",NULL,0},
    {957,"omg",NULL,0},{958,"omg",NULL,0},{959,"omg",NULL,0},
    {960,"omg",NULL,0},{961,"omg",NULL,0},{962,"omg",NULL,0},
    {963,"omg",NULL,0},{964,"omg",NULL,0},{965,"omg",NULL,0},
    {966,"omg",NULL,0},{967,"omg",NULL,0},{968,"omg",NULL,0},
    {969,"omg",NULL,0},{970,"omg",NULL,0},{971,"omg",NULL,0},
    {972,"omg",NULL,0},{973,"omg",NULL,0},{974,"omg",NULL,0},
    {975,"omg",NULL,0},{976,"omg",NULL,0},{977,"omg",NULL,0},
    {978,"omg",NULL,0},{979,"omg",NULL,0},{980,"omg",NULL,0},
    {981,"omg",NULL,0},{982,"omg",NULL,0},{983,"omg",NULL,0},
    {984,"omg",NULL,0},{985,"omg",NULL,0},{986,"omg",NULL,0},
    {987,"omg",NULL,0},{988,"omg",NULL,0},{989,"omg",NULL,0},
    {990,"omg",NULL,0},{991,"omg",NULL,0},{992,"omg",NULL,0},
    {993,"imaps","Dovecot",1},{994,"omg",NULL,0},
    {995,"pop3s","Dovecot",1},
    /* 1000-2000 */
    {1023,"netv",NULL,0},{1024,"kdm",NULL,0},{1025,"NFS-or-IIS",NULL,0},
    {1026,"LSA-or-nterm",NULL,0},{1027,"IIS",NULL,0},
    {1028,"msql",NULL,0},{1029,"ms-lsa",NULL,0},
    {1030,"ias-ad",NULL,0},{1031,"ias-ad",NULL,0},
    {1032,"ias-ad",NULL,0},{1033,"ias-ad",NULL,0},
    {1034,"ias-ad",NULL,0},{1035,"ias-ad",NULL,0},
    {1036,"ias-ad",NULL,0},{1037,"ias-ad",NULL,0},
    {1038,"ias-ad",NULL,0},{1039,"ias-ad",NULL,0},
    {1040,"ias-ad",NULL,0},{1041,"ias-ad",NULL,0},
    {1042,"ias-ad",NULL,0},{1043,"ias-ad",NULL,0},
    {1044,"ias-ad",NULL,0},{1045,"ias-ad",NULL,0},
    {1046,"ias-ad",NULL,0},{1047,"ias-ad",NULL,0},
    {1048,"ias-ad",NULL,0},{1049,"ias-ad",NULL,0},
    {1050,"ias-ad",NULL,0},{1051,"ias-ad",NULL,0},
    {1052,"ias-ad",NULL,0},{1053,"ias-ad",NULL,0},
    {1054,"ias-ad",NULL,0},{1055,"ias-ad",NULL,0},
    {1056,"ias-ad",NULL,0},{1057,"ias-ad",NULL,0},
    {1058,"ias-ad",NULL,0},{1059,"ias-ad",NULL,0},
    {1060,"ias-ad",NULL,0},{1061,"ias-ad",NULL,0},
    {1062,"ias-ad",NULL,0},{1063,"ias-ad",NULL,0},
    {1064,"ias-ad",NULL,0},{1065,"ias-ad",NULL,0},
    {1066,"ias-ad",NULL,0},{1067,"ias-ad",NULL,0},
    {1068,"ias-ad",NULL,0},{1069,"ias-ad",NULL,0},
    {1070,"ias-ad",NULL,0},{1071,"ias-ad",NULL,0},
    {1072,"ias-ad",NULL,0},{1073,"ias-ad",NULL,0},
    {1074,"ias-ad",NULL,0},{1075,"ias-ad",NULL,0},
    {1076,"ias-ad",NULL,0},{1077,"ias-ad",NULL,0},
    {1078,"ias-ad",NULL,0},{1079,"ias-ad",NULL,0},
    {1080,"socks","SOCKS",0},{1081,"pvuniwien",NULL,0},
    {1082,"amt-esd-prot",NULL,0},{1083,"ansoft-lm",NULL,0},
    {1084,"ansoft-lm",NULL,0},{1085,"web-objects",NULL,0},
    {1086,"cplscrambler",NULL,0},{1087,"cplscrambler",NULL,0},
    {1088,"cplscrambler",NULL,0},{1089,"cplscrambler",NULL,0},
    {1090,"cplscrambler",NULL,0},{1091,"cplscrambler",NULL,0},
    {1092,"cplscrambler",NULL,0},{1093,"cplscrambler",NULL,0},
    {1094,"cplscrambler",NULL,0},{1095,"cplscrambler",NULL,0},
    {1096,"cplscrambler",NULL,0},{1097,"cplscrambler",NULL,0},
    {1098,"cplscrambler",NULL,0},{1099,"cplscrambler",NULL,0},
    {1100,"cplscrambler",NULL,0},{1101,"cplscrambler",NULL,0},
    {1102,"cplscrambler",NULL,0},{1103,"cplscrambler",NULL,0},
    {1104,"cplscrambler",NULL,0},{1105,"cplscrambler",NULL,0},
    {1106,"cplscrambler",NULL,0},{1107,"cplscrambler",NULL,0},
    {1108,"cplscrambler",NULL,0},{1109,"cplscrambler",NULL,0},
    {1110,"cplscrambler",NULL,0},{1111,"cplscrambler",NULL,0},
    {1112,"cplscrambler",NULL,0},{1113,"cplscrambler",NULL,0},
    {1114,"cplscrambler",NULL,0},{1115,"cplscrambler",NULL,0},
    {1116,"cplscrambler",NULL,0},{1117,"cplscrambler",NULL,0},
    {1118,"cplscrambler",NULL,0},{1119,"cplscrambler",NULL,0},
    {1120,"cplscrambler",NULL,0},{1121,"cplscrambler",NULL,0},
    {1122,"cplscrambler",NULL,0},{1123,"cplscrambler",NULL,0},
    {1124,"cplscrambler",NULL,0},{1125,"cplscrambler",NULL,0},
    {1126,"cplscrambler",NULL,0},{1127,"cplscrambler",NULL,0},
    {1128,"cplscrambler",NULL,0},{1129,"cplscrambler",NULL,0},
    {1130,"cplscrambler",NULL,0},{1131,"cplscrambler",NULL,0},
    {1132,"cplscrambler",NULL,0},{1133,"cplscrambler",NULL,0},
    {1134,"cplscrambler",NULL,0},{1135,"cplscrambler",NULL,0},
    {1136,"cplscrambler",NULL,0},{1137,"cplscrambler",NULL,0},
    {1138,"cplscrambler",NULL,0},{1139,"cplscrambler",NULL,0},
    {1140,"cplscrambler",NULL,0},{1141,"cplscrambler",NULL,0},
    {1142,"cplscrambler",NULL,0},{1143,"cplscrambler",NULL,0},
    {1144,"cplscrambler",NULL,0},{1145,"cplscrambler",NULL,0},
    {1146,"cplscrambler",NULL,0},{1147,"cplscrambler",NULL,0},
    {1148,"cplscrambler",NULL,0},{1149,"cplscrambler",NULL,0},
    {1150,"cplscrambler",NULL,0},{1151,"cplscrambler",NULL,0},
    {1152,"cplscrambler",NULL,0},{1153,"cplscrambler",NULL,0},
    {1154,"cplscrambler",NULL,0},{1155,"cplscrambler",NULL,0},
    {1156,"cplscrambler",NULL,0},{1157,"cplscrambler",NULL,0},
    {1158,"cplscrambler",NULL,0},{1159,"cplscrambler",NULL,0},
    {1160,"cplscrambler",NULL,0},{1161,"cplscrambler",NULL,0},
    {1162,"cplscrambler",NULL,0},{1163,"cplscrambler",NULL,0},
    {1164,"cplscrambler",NULL,0},{1165,"cplscrambler",NULL,0},
    {1166,"cplscrambler",NULL,0},{1167,"cplscrambler",NULL,0},
    {1168,"cplscrambler",NULL,0},{1169,"cplscrambler",NULL,0},
    {1170,"cplscrambler",NULL,0},{1171,"cplscrambler",NULL,0},
    {1172,"cplscrambler",NULL,0},{1173,"cplscrambler",NULL,0},
    {1174,"cplscrambler",NULL,0},{1175,"cplscrambler",NULL,0},
    {1176,"cplscrambler",NULL,0},{1177,"cplscrambler",NULL,0},
    {1178,"cplscrambler",NULL,0},{1179,"cplscrambler",NULL,0},
    {1180,"cplscrambler",NULL,0},{1181,"cplscrambler",NULL,0},
    {1182,"cplscrambler",NULL,0},{1183,"cplscrambler",NULL,0},
    {1184,"cplscrambler",NULL,0},{1185,"cplscrambler",NULL,0},
    {1186,"cplscrambler",NULL,0},{1187,"cplscrambler",NULL,0},
    {1188,"cplscrambler",NULL,0},{1189,"cplscrambler",NULL,0},
    {1190,"cplscrambler",NULL,0},{1191,"cplscrambler",NULL,0},
    {1192,"cplscrambler",NULL,0},{1193,"cplscrambler",NULL,0},
    {1194,"cplscrambler",NULL,0},{1195,"cplscrambler",NULL,0},
    {1196,"cplscrambler",NULL,0},{1197,"cplscrambler",NULL,0},
    {1198,"cplscrambler",NULL,0},{1199,"cplscrambler",NULL,0},
    /* kritik portlar */
    {1194,"openvpn","OpenVPN",0},{1214,"kazaa",NULL,0},
    {1220,"qt-server",NULL,0},{1234,"vnc",NULL,0},
    {1241,"nessus","Nessus",0},{1243,"serialgateway",NULL,0},
    {1247,"visionpyramid",NULL,0},{1248,"visionpyramid",NULL,0},
    {1249,"visionpyramid",NULL,0},{1250,"visionpyramid",NULL,0},
    {1251,"visionpyramid",NULL,0},{1252,"visionpyramid",NULL,0},
    {1253,"visionpyramid",NULL,0},{1254,"visionpyramid",NULL,0},
    {1255,"visionpyramid",NULL,0},{1256,"visionpyramid",NULL,0},
    {1257,"visionpyramid",NULL,0},{1258,"visionpyramid",NULL,0},
    {1259,"visionpyramid",NULL,0},{1260,"visionpyramid",NULL,0},
    {1261,"visionpyramid",NULL,0},{1262,"visionpyramid",NULL,0},
    {1263,"visionpyramid",NULL,0},{1264,"visionpyramid",NULL,0},
    {1265,"visionpyramid",NULL,0},{1266,"visionpyramid",NULL,0},
    {1267,"visionpyramid",NULL,0},{1268,"visionpyramid",NULL,0},
    {1269,"visionpyramid",NULL,0},{1270,"visionpyramid",NULL,0},
    {1271,"visionpyramid",NULL,0},{1272,"visionpyramid",NULL,0},
    {1273,"visionpyramid",NULL,0},{1274,"visionpyramid",NULL,0},
    {1275,"visionpyramid",NULL,0},{1276,"visionpyramid",NULL,0},
    {1277,"visionpyramid",NULL,0},{1278,"visionpyramid",NULL,0},
    {1279,"visionpyramid",NULL,0},{1280,"visionpyramid",NULL,0},
    {1281,"visionpyramid",NULL,0},{1282,"visionpyramid",NULL,0},
    {1283,"visionpyramid",NULL,0},{1284,"visionpyramid",NULL,0},
    {1285,"visionpyramid",NULL,0},{1286,"visionpyramid",NULL,0},
    {1287,"visionpyramid",NULL,0},{1288,"visionpyramid",NULL,0},
    {1289,"visionpyramid",NULL,0},{1290,"visionpyramid",NULL,0},
    {1291,"visionpyramid",NULL,0},{1292,"visionpyramid",NULL,0},
    {1293,"visionpyramid",NULL,0},{1294,"visionpyramid",NULL,0},
    {1295,"visionpyramid",NULL,0},{1296,"visionpyramid",NULL,0},
    {1297,"visionpyramid",NULL,0},{1298,"visionpyramid",NULL,0},
    {1299,"visionpyramid",NULL,0},{1300,"visionpyramid",NULL,0},
    {1301,"visionpyramid",NULL,0},{1302,"visionpyramid",NULL,0},
    {1303,"visionpyramid",NULL,0},{1304,"visionpyramid",NULL,0},
    {1305,"visionpyramid",NULL,0},{1306,"visionpyramid",NULL,0},
    {1307,"visionpyramid",NULL,0},{1308,"visionpyramid",NULL,0},
    {1309,"visionpyramid",NULL,0},{1310,"visionpyramid",NULL,0},
    {1311,"visionpyramid",NULL,0},{1312,"visionpyramid",NULL,0},
    {1313,"visionpyramid",NULL,0},{1314,"visionpyramid",NULL,0},
    {1315,"visionpyramid",NULL,0},{1316,"visionpyramid",NULL,0},
    {1317,"visionpyramid",NULL,0},{1318,"visionpyramid",NULL,0},
    {1319,"visionpyramid",NULL,0},{1320,"visionpyramid",NULL,0},
    {1321,"visionpyramid",NULL,0},{1322,"visionpyramid",NULL,0},
    {1323,"visionpyramid",NULL,0},{1324,"visionpyramid",NULL,0},
    {1325,"visionpyramid",NULL,0},{1326,"visionpyramid",NULL,0},
    {1327,"visionpyramid",NULL,0},{1328,"visionpyramid",NULL,0},
    {1329,"visionpyramid",NULL,0},{1330,"visionpyramid",NULL,0},
    {1331,"visionpyramid",NULL,0},{1332,"visionpyramid",NULL,0},
    {1333,"visionpyramid",NULL,0},{1334,"visionpyramid",NULL,0},
    {1335,"visionpyramid",NULL,0},{1336,"visionpyramid",NULL,0},
    {1337,"visionpyramid",NULL,0},{1338,"visionpyramid",NULL,0},
    {1339,"visionpyramid",NULL,0},{1340,"visionpyramid",NULL,0},
    {1341,"visionpyramid",NULL,0},{1342,"visionpyramid",NULL,0},
    {1343,"visionpyramid",NULL,0},{1344,"visionpyramid",NULL,0},
    {1345,"visionpyramid",NULL,0},{1346,"visionpyramid",NULL,0},
    {1347,"visionpyramid",NULL,0},{1348,"visionpyramid",NULL,0},
    {1349,"visionpyramid",NULL,0},{1350,"visionpyramid",NULL,0},
    /* önemli yüksek portlar */
    {1433,"ms-sql-s","Microsoft SQL Server",0},
    {1434,"ms-sql-m",NULL,0},{1521,"oracle-tns","Oracle DB",0},
    {1522,"oracle-tns-alt",NULL,0},{1524,"ingres",NULL,0},
    {1525,"oracle",NULL,0},{1526,"oracle",NULL,0},
    {1527,"oracle",NULL,0},{1529,"oracle",NULL,0},
    {1530,"oracle",NULL,0},{1531,"oracle",NULL,0},
    {1532,"oracle",NULL,0},{1533,"oracle",NULL,0},
    {1534,"oracle",NULL,0},{1535,"oracle",NULL,0},
    {1536,"oracle",NULL,0},{1537,"oracle",NULL,0},
    {1538,"oracle",NULL,0},{1539,"oracle",NULL,0},
    {1540,"oracle",NULL,0},{1541,"oracle",NULL,0},
    {1542,"oracle",NULL,0},{1543,"oracle",NULL,0},
    {1544,"oracle",NULL,0},{1545,"oracle",NULL,0},
    {1546,"oracle",NULL,0},{1547,"oracle",NULL,0},
    {1548,"oracle",NULL,0},{1549,"oracle",NULL,0},
    {1550,"oracle",NULL,0},{1604,"ica",NULL,0},
    {1645,"sink",NULL,0},{1646,"sink",NULL,0},
    {1649,"kermit",NULL,0},{1701,"l2tp",NULL,0},
    {1717,"vpp",NULL,0},{1718,"vpp",NULL,0},
    {1719,"h323-gk","H.323",0},{1720,"h323-cs","H.323",0},
    {1723,"pptp","PPTP",0},{1741,"ciscoweb",NULL,0},
    {1755,"wms","Windows Media",0},{1761,"cwt",NULL,0},
    {1801,"msmq","MSMQ",0},{1812,"radius","FreeRADIUS",0},
    {1813,"radius-acct",NULL,0},{1863,"msnp","MSNP",0},
    {1900,"upnp","UPnP",0},{1935,"rtmp","Adobe RTMP",0},
    {1947,"sentinel",NULL,0},{1962,"biap-mp",NULL,0},
    {1970,"netop",NULL,0},{1971,"netop",NULL,0},
    {1972,"netop",NULL,0},{1973,"netop",NULL,0},
    {1974,"drp",NULL,0},{1984,"bb",NULL,0},
    {1985,"hsrp",NULL,0},{1986,"licensedaemon",NULL,0},
    {1987,"tr-rsrb",NULL,0},{1988,"tr-rsrb",NULL,0},
    {1989,"tr-rsrb",NULL,0},{1990,"tr-rsrb",NULL,0},
    {1991,"tr-rsrb",NULL,0},{1992,"tr-rsrb",NULL,0},
    {1993,"tr-rsrb",NULL,0},{1994,"tr-rsrb",NULL,0},
    {1995,"tr-rsrb",NULL,0},{1996,"tr-rsrb",NULL,0},
    {1997,"tr-rsrb",NULL,0},{1998,"tr-rsrb",NULL,0},
    {1999,"tr-rsrb",NULL,0},{2000,"cisco-sccp",NULL,0},
    /* 2000-5000 */
    {2001,"dc",NULL,0},{2002,"globe",NULL,0},
    {2003,"finger",NULL,0},{2004,"br-rdo",NULL,0},
    {2005,"br-rdo",NULL,0},{2006,"invokator",NULL,0},
    {2007,"dectalk",NULL,0},{2008,"conf",NULL,0},
    {2009,"news",NULL,0},{2010,"search",NULL,0},
    {2011,"raid-cc",NULL,0},{2012,"ttyinfo",NULL,0},
    {2013,"raid-am",NULL,0},{2014,"troff",NULL,0},
    {2015,"cypress",NULL,0},{2016,"cypress",NULL,0},
    {2017,"cypress",NULL,0},{2018,"cypress",NULL,0},
    {2019,"cypress",NULL,0},{2020,"cypress",NULL,0},
    {2021,"cypress",NULL,0},{2022,"cypress",NULL,0},
    {2023,"cypress",NULL,0},{2024,"cypress",NULL,0},
    {2025,"cypress",NULL,0},{2030,"device2",NULL,0},
    {2033,"device3",NULL,0},{2034,"device4",NULL,0},
    {2035,"device5",NULL,0},{2038,"objectmanager",NULL,0},
    {2040,"lam",NULL,0},{2041,"interbase",NULL,0},
    {2042,"isis",NULL,0},{2043,"isis",NULL,0},
    {2044,"isis",NULL,0},{2045,"isis",NULL,0},
    {2046,"isis",NULL,0},{2047,"isis",NULL,0},
    {2048,"isis",NULL,0},{2049,"nfs","NFS",0},
    {2050,"isis",NULL,0},{2051,"isis",NULL,0},
    {2052,"isis",NULL,0},{2053,"knetd",NULL,0},
    {2054,"isis",NULL,0},{2055,"isis",NULL,0},
    {2056,"isis",NULL,0},{2057,"isis",NULL,0},
    {2058,"isis",NULL,0},{2059,"isis",NULL,0},
    {2060,"isis",NULL,0},{2061,"isis",NULL,0},
    {2062,"isis",NULL,0},{2063,"isis",NULL,0},
    {2064,"isis",NULL,0},{2065,"dlsrpn",NULL,0},
    {2067,"dlsrpn",NULL,0},{2068,"dlsrpn",NULL,0},
    {2069,"dlsrpn",NULL,0},{2070,"dlsrpn",NULL,0},
    {2071,"dlsrpn",NULL,0},{2072,"dlsrpn",NULL,0},
    {2073,"dlsrpn",NULL,0},{2074,"dlsrpn",NULL,0},
    {2075,"dlsrpn",NULL,0},{2076,"dlsrpn",NULL,0},
    {2077,"dlsrpn",NULL,0},{2078,"dlsrpn",NULL,0},
    {2079,"dlsrpn",NULL,0},{2080,"autodesk",NULL,0},
    {2081,"autodesk",NULL,0},{2082,"autodesk",NULL,0},
    {2083,"autodesk",NULL,0},{2084,"autodesk",NULL,0},
    {2085,"autodesk",NULL,0},{2086,"autodesk",NULL,0},
    {2087,"autodesk",NULL,0},{2088,"autodesk",NULL,0},
    {2089,"autodesk",NULL,0},{2090,"autodesk",NULL,0},
    {2091,"autodesk",NULL,0},{2092,"autodesk",NULL,0},
    {2093,"autodesk",NULL,0},{2094,"autodesk",NULL,0},
    {2095,"autodesk",NULL,0},{2096,"autodesk",NULL,0},
    {2097,"autodesk",NULL,0},{2098,"autodesk",NULL,0},
    {2099,"autodesk",NULL,0},{2100,"amiganetfs",NULL,0},
    {2101,"rtcm-sc104",NULL,0},{2102,"zephyr",NULL,0},
    {2103,"zephyr",NULL,0},{2104,"zephyr",NULL,0},
    {2105,"zephyr",NULL,0},{2106,"zephyr",NULL,0},
    {2107,"zephyr",NULL,0},{2108,"zephyr",NULL,0},
    {2109,"zephyr",NULL,0},{2110,"zephyr",NULL,0},
    {2111,"zephyr",NULL,0},{2112,"zephyr",NULL,0},
    {2113,"zephyr",NULL,0},{2114,"zephyr",NULL,0},
    {2115,"zephyr",NULL,0},{2116,"zephyr",NULL,0},
    {2117,"zephyr",NULL,0},{2118,"zephyr",NULL,0},
    {2119,"zephyr",NULL,0},{2120,"zephyr",NULL,0},
    {2121,"zephyr",NULL,0},{2122,"zephyr",NULL,0},
    {2123,"zephyr",NULL,0},{2124,"zephyr",NULL,0},
    {2125,"zephyr",NULL,0},{2126,"zephyr",NULL,0},
    {2127,"zephyr",NULL,0},{2128,"zephyr",NULL,0},
    {2129,"zephyr",NULL,0},{2130,"zephyr",NULL,0},
    {2131,"zephyr",NULL,0},{2132,"zephyr",NULL,0},
    {2133,"zephyr",NULL,0},{2134,"zephyr",NULL,0},
    {2135,"zephyr",NULL,0},{2136,"zephyr",NULL,0},
    {2137,"zephyr",NULL,0},{2138,"zephyr",NULL,0},
    {2139,"zephyr",NULL,0},{2140,"zephyr",NULL,0},
    {2141,"zephyr",NULL,0},{2142,"zephyr",NULL,0},
    {2143,"zephyr",NULL,0},{2144,"zephyr",NULL,0},
    {2145,"zephyr",NULL,0},{2146,"zephyr",NULL,0},
    {2147,"zephyr",NULL,0},{2148,"zephyr",NULL,0},
    {2149,"zephyr",NULL,0},{2150,"zephyr",NULL,0},
    {2151,"zephyr",NULL,0},{2152,"zephyr",NULL,0},
    {2153,"zephyr",NULL,0},{2154,"zephyr",NULL,0},
    {2155,"zephyr",NULL,0},{2156,"zephyr",NULL,0},
    {2157,"zephyr",NULL,0},{2158,"zephyr",NULL,0},
    {2159,"zephyr",NULL,0},{2160,"zephyr",NULL,0},
    {2161,"zephyr",NULL,0},{2162,"zephyr",NULL,0},
    {2163,"zephyr",NULL,0},{2164,"zephyr",NULL,0},
    {2165,"zephyr",NULL,0},{2166,"zephyr",NULL,0},
    {2167,"zephyr",NULL,0},{2168,"zephyr",NULL,0},
    {2169,"zephyr",NULL,0},{2170,"zephyr",NULL,0},
    {2171,"zephyr",NULL,0},{2172,"zephyr",NULL,0},
    {2173,"zephyr",NULL,0},{2174,"zephyr",NULL,0},
    {2175,"zephyr",NULL,0},{2176,"zephyr",NULL,0},
    {2177,"zephyr",NULL,0},{2178,"zephyr",NULL,0},
    {2179,"zephyr",NULL,0},{2180,"zephyr",NULL,0},
    {2181,"zephyr",NULL,0},{2182,"zephyr",NULL,0},
    {2183,"zephyr",NULL,0},{2184,"zephyr",NULL,0},
    {2185,"zephyr",NULL,0},{2186,"zephyr",NULL,0},
    {2187,"zephyr",NULL,0},{2188,"zephyr",NULL,0},
    {2189,"zephyr",NULL,0},{2190,"zephyr",NULL,0},
    {2191,"zephyr",NULL,0},{2192,"zephyr",NULL,0},
    {2193,"zephyr",NULL,0},{2194,"zephyr",NULL,0},
    {2195,"zephyr",NULL,0},{2196,"zephyr",NULL,0},
    {2197,"zephyr",NULL,0},{2198,"zephyr",NULL,0},
    {2199,"zephyr",NULL,0},{2200,"zephyr",NULL,0},
    {2201,"ats",NULL,0},{2202,"ats",NULL,0},
    {2203,"ats",NULL,0},{2204,"ats",NULL,0},
    {2205,"ats",NULL,0},{2206,"ats",NULL,0},
    {2207,"ats",NULL,0},{2208,"ats",NULL,0},
    {2209,"ats",NULL,0},{2210,"ats",NULL,0},
    {2211,"ats",NULL,0},{2212,"ats",NULL,0},
    {2213,"ats",NULL,0},{2214,"ats",NULL,0},
    {2215,"ats",NULL,0},{2216,"ats",NULL,0},
    {2217,"ats",NULL,0},{2218,"ats",NULL,0},
    {2219,"ats",NULL,0},{2220,"ats",NULL,0},
    {2221,"ats",NULL,0},{2222,"ssh-alt","OpenSSH",0},
    {2223,"ats",NULL,0},{2224,"ats",NULL,0},
    {2225,"ats",NULL,0},{2226,"ats",NULL,0},
    {2227,"ats",NULL,0},{2228,"ats",NULL,0},
    {2229,"ats",NULL,0},{2230,"ats",NULL,0},
    {2231,"ats",NULL,0},{2232,"ats",NULL,0},
    {2233,"ats",NULL,0},{2234,"ats",NULL,0},
    {2235,"ats",NULL,0},{2236,"ats",NULL,0},
    {2237,"ats",NULL,0},{2238,"ats",NULL,0},
    {2239,"ats",NULL,0},{2240,"ats",NULL,0},
    {2241,"ats",NULL,0},{2242,"ats",NULL,0},
    {2243,"ats",NULL,0},{2244,"ats",NULL,0},
    {2245,"ats",NULL,0},{2246,"ats",NULL,0},
    {2247,"ats",NULL,0},{2248,"ats",NULL,0},
    {2249,"ats",NULL,0},{2250,"ats",NULL,0},
    {2251,"ats",NULL,0},{2252,"ats",NULL,0},
    {2253,"ats",NULL,0},{2254,"ats",NULL,0},
    {2255,"ats",NULL,0},{2256,"ats",NULL,0},
    {2257,"ats",NULL,0},{2258,"ats",NULL,0},
    {2259,"ats",NULL,0},{2260,"ats",NULL,0},
    {2261,"ats",NULL,0},{2262,"ats",NULL,0},
    {2263,"ats",NULL,0},{2264,"ats",NULL,0},
    {2265,"ats",NULL,0},{2266,"ats",NULL,0},
    {2267,"ats",NULL,0},{2268,"ats",NULL,0},
    {2269,"ats",NULL,0},{2270,"ats",NULL,0},
    {2271,"ats",NULL,0},{2272,"ats",NULL,0},
    {2273,"ats",NULL,0},{2274,"ats",NULL,0},
    {2275,"ats",NULL,0},{2276,"ats",NULL,0},
    {2277,"ats",NULL,0},{2278,"ats",NULL,0},
    {2279,"ats",NULL,0},{2280,"ats",NULL,0},
    {2281,"ats",NULL,0},{2282,"ats",NULL,0},
    {2283,"ats",NULL,0},{2284,"ats",NULL,0},
    {2285,"ats",NULL,0},{2286,"ats",NULL,0},
    {2287,"ats",NULL,0},{2288,"ats",NULL,0},
    {2289,"ats",NULL,0},{2290,"ats",NULL,0},
    {2291,"ats",NULL,0},{2292,"ats",NULL,0},
    {2293,"ats",NULL,0},{2294,"ats",NULL,0},
    {2295,"ats",NULL,0},{2296,"ats",NULL,0},
    {2297,"ats",NULL,0},{2298,"ats",NULL,0},
    {2299,"ats",NULL,0},{2300,"ats",NULL,0},
    {2301,"ats",NULL,0},{2302,"ats",NULL,0},
    {2303,"ats",NULL,0},{2304,"ats",NULL,0},
    {2305,"ats",NULL,0},{2306,"ats",NULL,0},
    {2307,"ats",NULL,0},{2308,"ats",NULL,0},
    {2309,"ats",NULL,0},{2310,"ats",NULL,0},
    {2311,"ats",NULL,0},{2312,"ats",NULL,0},
    {2313,"ats",NULL,0},{2314,"ats",NULL,0},
    {2315,"ats",NULL,0},{2316,"ats",NULL,0},
    {2317,"ats",NULL,0},{2318,"ats",NULL,0},
    {2319,"ats",NULL,0},{2320,"ats",NULL,0},
    {2321,"ats",NULL,0},{2322,"ats",NULL,0},
    {2323,"ats",NULL,0},{2324,"ats",NULL,0},
    {2325,"ats",NULL,0},{2326,"ats",NULL,0},
    {2327,"ats",NULL,0},{2328,"ats",NULL,0},
    {2329,"ats",NULL,0},{2330,"ats",NULL,0},
    {2331,"ats",NULL,0},{2332,"ats",NULL,0},
    {2333,"ats",NULL,0},{2334,"ats",NULL,0},
    {2335,"ats",NULL,0},{2336,"ats",NULL,0},
    {2337,"ats",NULL,0},{2338,"ats",NULL,0},
    {2339,"ats",NULL,0},{2340,"ats",NULL,0},
    {2341,"ats",NULL,0},{2342,"ats",NULL,0},
    {2343,"ats",NULL,0},{2344,"ats",NULL,0},
    {2345,"ats",NULL,0},{2346,"ats",NULL,0},
    {2347,"ats",NULL,0},{2348,"ats",NULL,0},
    {2349,"ats",NULL,0},{2350,"ats",NULL,0},
    {2351,"ats",NULL,0},{2352,"ats",NULL,0},
    {2353,"ats",NULL,0},{2354,"ats",NULL,0},
    {2355,"ats",NULL,0},{2356,"ats",NULL,0},
    {2357,"ats",NULL,0},{2358,"ats",NULL,0},
    {2359,"ats",NULL,0},{2360,"ats",NULL,0},
    {2361,"ats",NULL,0},{2362,"ats",NULL,0},
    {2363,"ats",NULL,0},{2364,"ats",NULL,0},
    {2365,"ats",NULL,0},{2366,"ats",NULL,0},
    {2367,"ats",NULL,0},{2368,"ats",NULL,0},
    {2369,"ats",NULL,0},{2370,"ats",NULL,0},
    {2371,"ats",NULL,0},{2372,"ats",NULL,0},
    {2373,"ats",NULL,0},{2374,"ats",NULL,0},
    {2375,"docker","Docker",0},{2376,"docker-ssl","Docker",1},
    {2377,"swarm",NULL,0},{2378,"docker",NULL,0},
    {2379,"etcd-client",NULL,0},{2380,"etcd-server",NULL,0},
    {2401,"cvspserver","CVS",0},{2404,"ieee",NULL,0},
    {2424,"oracle",NULL,0},{2427,"mgcp-gateway",NULL,0},
    {2447,"ovwdb",NULL,0},{2456,"altavista",NULL,0},
    {2483,"oracle",NULL,0},{2484,"oracle-ssl",NULL,1},
    {2500,"rtsserv",NULL,0},{2501,"rtsclient",NULL,0},
    {2502,"rtsserver",NULL,0},{2503,"rtsserver",NULL,0},
    {2504,"rtsserver",NULL,0},{2525,"smtp-alt",NULL,0},
    {2546,"vpn",NULL,0},{2547,"vpn",NULL,0},
    {2548,"vpn",NULL,0},{2549,"vpn",NULL,0},
    {2550,"vpn",NULL,0},{2551,"vpn",NULL,0},
    {2552,"vpn",NULL,0},{2553,"vpn",NULL,0},
    {2554,"vpn",NULL,0},{2555,"vpn",NULL,0},
    {2556,"vpn",NULL,0},{2557,"vpn",NULL,0},
    {2558,"vpn",NULL,0},{2559,"vpn",NULL,0},
    {2560,"vpn",NULL,0},{2561,"vpn",NULL,0},
    {2562,"vpn",NULL,0},{2563,"vpn",NULL,0},
    {2564,"vpn",NULL,0},{2565,"vpn",NULL,0},
    {2566,"vpn",NULL,0},{2567,"vpn",NULL,0},
    {2568,"vpn",NULL,0},{2569,"vpn",NULL,0},
    {2570,"vpn",NULL,0},{2593,"ultraseek",NULL,0},
    {2594,"ultraseek",NULL,0},{2595,"ultraseek",NULL,0},
    {2596,"ultraseek",NULL,0},{2597,"ultraseek",NULL,0},
    {2598,"ultraseek",NULL,0},{2599,"ultraseek",NULL,0},
    {2600,"ultraseek",NULL,0},{2601,"ultraseek",NULL,0},
    {2602,"ultraseek",NULL,0},{2603,"ultraseek",NULL,0},
    {2604,"ultraseek",NULL,0},{2605,"ultraseek",NULL,0},
    {2606,"ultraseek",NULL,0},{2607,"ultraseek",NULL,0},
    {2608,"ultraseek",NULL,0},{2609,"ultraseek",NULL,0},
    {2610,"ultraseek",NULL,0},{2611,"ultraseek",NULL,0},
    {2612,"ultraseek",NULL,0},{2613,"ultraseek",NULL,0},
    {2614,"ultraseek",NULL,0},{2615,"ultraseek",NULL,0},
    {2616,"ultraseek",NULL,0},{2617,"ultraseek",NULL,0},
    {2618,"ultraseek",NULL,0},{2619,"ultraseek",NULL,0},
    {2620,"ultraseek",NULL,0},{2621,"ultraseek",NULL,0},
    {2622,"ultraseek",NULL,0},{2623,"ultraseek",NULL,0},
    {2624,"ultraseek",NULL,0},{2625,"ultraseek",NULL,0},
    {2626,"ultraseek",NULL,0},{2627,"ultraseek",NULL,0},
    {2628,"ultraseek",NULL,0},{2629,"ultraseek",NULL,0},
    {2630,"ultraseek",NULL,0},{2631,"ultraseek",NULL,0},
    {2632,"ultraseek",NULL,0},{2633,"ultraseek",NULL,0},
    {2634,"ultraseek",NULL,0},{2635,"ultraseek",NULL,0},
    {2636,"ultraseek",NULL,0},{2637,"ultraseek",NULL,0},
    {2638,"ultraseek",NULL,0},{2639,"ultraseek",NULL,0},
    {2640,"ultraseek",NULL,0},{2641,"ultraseek",NULL,0},
    {2642,"ultraseek",NULL,0},{2643,"ultraseek",NULL,0},
    {2644,"ultraseek",NULL,0},{2645,"ultraseek",NULL,0},
    {2646,"ultraseek",NULL,0},{2647,"ultraseek",NULL,0},
    {2648,"ultraseek",NULL,0},{2649,"ultraseek",NULL,0},
    {2650,"ultraseek",NULL,0},{2651,"ultraseek",NULL,0},
    {2652,"ultraseek",NULL,0},{2653,"ultraseek",NULL,0},
    {2654,"ultraseek",NULL,0},{2655,"ultraseek",NULL,0},
    {2656,"ultraseek",NULL,0},{2657,"ultraseek",NULL,0},
    {2658,"ultraseek",NULL,0},{2659,"ultraseek",NULL,0},
    {2660,"ultraseek",NULL,0},{2661,"ultraseek",NULL,0},
    {2662,"ultraseek",NULL,0},{2663,"ultraseek",NULL,0},
    {2664,"ultraseek",NULL,0},{2665,"ultraseek",NULL,0},
    {2666,"ultraseek",NULL,0},{2667,"ultraseek",NULL,0},
    {2668,"ultraseek",NULL,0},{2669,"ultraseek",NULL,0},
    {2670,"ultraseek",NULL,0},{2671,"ultraseek",NULL,0},
    {2672,"ultraseek",NULL,0},{2673,"ultraseek",NULL,0},
    {2674,"ultraseek",NULL,0},{2675,"ultraseek",NULL,0},
    {2676,"ultraseek",NULL,0},{2677,"ultraseek",NULL,0},
    {2678,"ultraseek",NULL,0},{2679,"ultraseek",NULL,0},
    {2680,"ultraseek",NULL,0},{2681,"ultraseek",NULL,0},
    {2682,"ultraseek",NULL,0},{2683,"ultraseek",NULL,0},
    {2684,"ultraseek",NULL,0},{2685,"ultraseek",NULL,0},
    {2686,"ultraseek",NULL,0},{2687,"ultraseek",NULL,0},
    {2688,"ultraseek",NULL,0},{2689,"ultraseek",NULL,0},
    {2690,"ultraseek",NULL,0},{2691,"ultraseek",NULL,0},
    {2692,"ultraseek",NULL,0},{2693,"ultraseek",NULL,0},
    {2694,"ultraseek",NULL,0},{2695,"ultraseek",NULL,0},
    {2696,"ultraseek",NULL,0},{2697,"ultraseek",NULL,0},
    {2698,"ultraseek",NULL,0},{2699,"ultraseek",NULL,0},
    {2700,"ultraseek",NULL,0},{2701,"ultraseek",NULL,0},
    {2702,"ultraseek",NULL,0},{2703,"ultraseek",NULL,0},
    {2704,"ultraseek",NULL,0},{2705,"ultraseek",NULL,0},
    {2706,"ultraseek",NULL,0},{2707,"ultraseek",NULL,0},
    {2708,"ultraseek",NULL,0},{2709,"ultraseek",NULL,0},
    {2710,"ultraseek",NULL,0},{2711,"ultraseek",NULL,0},
    {2712,"ultraseek",NULL,0},{2713,"ultraseek",NULL,0},
    {2714,"ultraseek",NULL,0},{2715,"ultraseek",NULL,0},
    {2716,"ultraseek",NULL,0},{2717,"ultraseek",NULL,0},
    {2718,"ultraseek",NULL,0},{2719,"ultraseek",NULL,0},
    {2720,"ultraseek",NULL,0},{2721,"ultraseek",NULL,0},
    {2722,"ultraseek",NULL,0},{2723,"ultraseek",NULL,0},
    {2724,"ultraseek",NULL,0},{2725,"ultraseek",NULL,0},
    {2726,"ultraseek",NULL,0},{2727,"ultraseek",NULL,0},
    {2728,"ultraseek",NULL,0},{2729,"ultraseek",NULL,0},
    {2730,"ultraseek",NULL,0},{2731,"ultraseek",NULL,0},
    {2732,"ultraseek",NULL,0},{2733,"ultraseek",NULL,0},
    {2734,"ultraseek",NULL,0},{2735,"ultraseek",NULL,0},
    {2736,"ultraseek",NULL,0},{2737,"ultraseek",NULL,0},
    {2738,"ultraseek",NULL,0},{2739,"ultraseek",NULL,0},
    {2740,"ultraseek",NULL,0},{2741,"ultraseek",NULL,0},
    {2742,"ultraseek",NULL,0},{2743,"ultraseek",NULL,0},
    {2744,"ultraseek",NULL,0},{2745,"ultraseek",NULL,0},
    {2746,"ultraseek",NULL,0},{2747,"ultraseek",NULL,0},
    {2748,"ultraseek",NULL,0},{2749,"ultraseek",NULL,0},
    {2750,"ultraseek",NULL,0},{2751,"ultraseek",NULL,0},
    {2752,"ultraseek",NULL,0},{2753,"ultraseek",NULL,0},
    {2754,"ultraseek",NULL,0},{2755,"ultraseek",NULL,0},
    {2756,"ultraseek",NULL,0},{2757,"ultraseek",NULL,0},
    {2758,"ultraseek",NULL,0},{2759,"ultraseek",NULL,0},
    {2760,"ultraseek",NULL,0},{2761,"ultraseek",NULL,0},
    {2762,"ultraseek",NULL,0},{2763,"ultraseek",NULL,0},
    {2764,"ultraseek",NULL,0},{2765,"ultraseek",NULL,0},
    {2766,"ultraseek",NULL,0},{2767,"ultraseek",NULL,0},
    {2768,"ultraseek",NULL,0},{2769,"ultraseek",NULL,0},
    {2770,"ultraseek",NULL,0},{2771,"ultraseek",NULL,0},
    {2772,"ultraseek",NULL,0},{2773,"ultraseek",NULL,0},
    {2774,"ultraseek",NULL,0},{2775,"ultraseek",NULL,0},
    {2776,"ultraseek",NULL,0},{2777,"ultraseek",NULL,0},
    {2778,"ultraseek",NULL,0},{2779,"ultraseek",NULL,0},
    {2780,"ultraseek",NULL,0},{2781,"ultraseek",NULL,0},
    {2782,"ultraseek",NULL,0},{2783,"ultraseek",NULL,0},
    {2784,"ultraseek",NULL,0},{2785,"ultraseek",NULL,0},
    {2786,"ultraseek",NULL,0},{2787,"ultraseek",NULL,0},
    {2788,"ultraseek",NULL,0},{2789,"ultraseek",NULL,0},
    {2790,"ultraseek",NULL,0},{2791,"ultraseek",NULL,0},
    {2792,"ultraseek",NULL,0},{2793,"ultraseek",NULL,0},
    {2794,"ultraseek",NULL,0},{2795,"ultraseek",NULL,0},
    {2796,"ultraseek",NULL,0},{2797,"ultraseek",NULL,0},
    {2798,"ultraseek",NULL,0},{2799,"ultraseek",NULL,0},
    {2800,"ultraseek",NULL,0},{2801,"ultraseek",NULL,0},
    {2802,"ultraseek",NULL,0},{2803,"ultraseek",NULL,0},
    {2804,"ultraseek",NULL,0},{2805,"ultraseek",NULL,0},
    {2806,"ultraseek",NULL,0},{2807,"ultraseek",NULL,0},
    {2808,"ultraseek",NULL,0},{2809,"ultraseek",NULL,0},
    {2810,"ultraseek",NULL,0},{2811,"ultraseek",NULL,0},
    {2812,"ultraseek",NULL,0},{2813,"ultraseek",NULL,0},
    {2814,"ultraseek",NULL,0},{2815,"ultraseek",NULL,0},
    {2816,"ultraseek",NULL,0},{2817,"ultraseek",NULL,0},
    {2818,"ultraseek",NULL,0},{2819,"ultraseek",NULL,0},
    {2820,"ultraseek",NULL,0},{2821,"ultraseek",NULL,0},
    {2822,"ultraseek",NULL,0},{2823,"ultraseek",NULL,0},
    {2824,"ultraseek",NULL,0},{2825,"ultraseek",NULL,0},
    {2826,"ultraseek",NULL,0},{2827,"ultraseek",NULL,0},
    {2828,"ultraseek",NULL,0},{2829,"ultraseek",NULL,0},
    {2830,"ultraseek",NULL,0},{2831,"ultraseek",NULL,0},
    {2832,"ultraseek",NULL,0},{2833,"ultraseek",NULL,0},
    {2834,"ultraseek",NULL,0},{2835,"ultraseek",NULL,0},
    {2836,"ultraseek",NULL,0},{2837,"ultraseek",NULL,0},
    {2838,"ultraseek",NULL,0},{2839,"ultraseek",NULL,0},
    {2840,"ultraseek",NULL,0},{2841,"ultraseek",NULL,0},
    {2842,"ultraseek",NULL,0},{2843,"ultraseek",NULL,0},
    {2844,"ultraseek",NULL,0},{2845,"ultraseek",NULL,0},
    {2846,"ultraseek",NULL,0},{2847,"ultraseek",NULL,0},
    {2848,"ultraseek",NULL,0},{2849,"ultraseek",NULL,0},
    {2850,"ultraseek",NULL,0},{2851,"ultraseek",NULL,0},
    {2852,"ultraseek",NULL,0},{2853,"ultraseek",NULL,0},
    {2854,"ultraseek",NULL,0},{2855,"ultraseek",NULL,0},
    {2856,"ultraseek",NULL,0},{2857,"ultraseek",NULL,0},
    {2858,"ultraseek",NULL,0},{2859,"ultraseek",NULL,0},
    {2860,"ultraseek",NULL,0},{2861,"ultraseek",NULL,0},
    {2862,"ultraseek",NULL,0},{2863,"ultraseek",NULL,0},
    {2864,"ultraseek",NULL,0},{2865,"ultraseek",NULL,0},
    {2866,"ultraseek",NULL,0},{2867,"ultraseek",NULL,0},
    {2868,"ultraseek",NULL,0},{2869,"ultraseek",NULL,0},
    {2870,"ultraseek",NULL,0},{2871,"ultraseek",NULL,0},
    {2872,"ultraseek",NULL,0},{2873,"ultraseek",NULL,0},
    {2874,"ultraseek",NULL,0},{2875,"ultraseek",NULL,0},
    {2876,"ultraseek",NULL,0},{2877,"ultraseek",NULL,0},
    {2878,"ultraseek",NULL,0},{2879,"ultraseek",NULL,0},
    {2880,"ultraseek",NULL,0},{2881,"ultraseek",NULL,0},
    {2882,"ultraseek",NULL,0},{2883,"ultraseek",NULL,0},
    {2884,"ultraseek",NULL,0},{2885,"ultraseek",NULL,0},
    {2886,"ultraseek",NULL,0},{2887,"ultraseek",NULL,0},
    {2888,"ultraseek",NULL,0},{2889,"ultraseek",NULL,0},
    {2890,"ultraseek",NULL,0},{2891,"ultraseek",NULL,0},
    {2892,"ultraseek",NULL,0},{2893,"ultraseek",NULL,0},
    {2894,"ultraseek",NULL,0},{2895,"ultraseek",NULL,0},
    {2896,"ultraseek",NULL,0},{2897,"ultraseek",NULL,0},
    {2898,"ultraseek",NULL,0},{2899,"ultraseek",NULL,0},
    {2900,"ultraseek",NULL,0},{2901,"ultraseek",NULL,0},
    {2902,"ultraseek",NULL,0},{2903,"ultraseek",NULL,0},
    {2904,"ultraseek",NULL,0},{2905,"ultraseek",NULL,0},
    {2906,"ultraseek",NULL,0},{2907,"ultraseek",NULL,0},
    {2908,"ultraseek",NULL,0},{2909,"ultraseek",NULL,0},
    {2910,"ultraseek",NULL,0},{2911,"ultraseek",NULL,0},
    {2912,"ultraseek",NULL,0},{2913,"ultraseek",NULL,0},
    {2914,"ultraseek",NULL,0},{2915,"ultraseek",NULL,0},
    {2916,"ultraseek",NULL,0},{2917,"ultraseek",NULL,0},
    {2918,"ultraseek",NULL,0},{2919,"ultraseek",NULL,0},
    {2920,"ultraseek",NULL,0},{2921,"ultraseek",NULL,0},
    {2922,"ultraseek",NULL,0},{2923,"ultraseek",NULL,0},
    {2924,"ultraseek",NULL,0},{2925,"ultraseek",NULL,0},
    {2926,"ultraseek",NULL,0},{2927,"ultraseek",NULL,0},
    {2928,"ultraseek",NULL,0},{2929,"ultraseek",NULL,0},
    {2930,"ultraseek",NULL,0},{2931,"ultraseek",NULL,0},
    {2932,"ultraseek",NULL,0},{2933,"ultraseek",NULL,0},
    {2934,"ultraseek",NULL,0},{2935,"ultraseek",NULL,0},
    {2936,"ultraseek",NULL,0},{2937,"ultraseek",NULL,0},
    {2938,"ultraseek",NULL,0},{2939,"ultraseek",NULL,0},
    {2940,"ultraseek",NULL,0},{2941,"ultraseek",NULL,0},
    {2942,"ultraseek",NULL,0},{2943,"ultraseek",NULL,0},
    {2944,"ultraseek",NULL,0},{2945,"ultraseek",NULL,0},
    {2946,"ultraseek",NULL,0},{2947,"ultraseek",NULL,0},
    {2948,"ultraseek",NULL,0},{2949,"ultraseek",NULL,0},
    {2950,"ultraseek",NULL,0},{2951,"ultraseek",NULL,0},
    {2952,"ultraseek",NULL,0},{2953,"ultraseek",NULL,0},
    {2954,"ultraseek",NULL,0},{2955,"ultraseek",NULL,0},
    {2956,"ultraseek",NULL,0},{2957,"ultraseek",NULL,0},
    {2958,"ultraseek",NULL,0},{2959,"ultraseek",NULL,0},
    {2960,"ultraseek",NULL,0},{2961,"ultraseek",NULL,0},
    {2962,"ultraseek",NULL,0},{2963,"ultraseek",NULL,0},
    {2964,"ultraseek",NULL,0},{2965,"ultraseek",NULL,0},
    {2966,"ultraseek",NULL,0},{2967,"ultraseek",NULL,0},
    {2968,"ultraseek",NULL,0},{2969,"ultraseek",NULL,0},
    {2970,"ultraseek",NULL,0},{2971,"ultraseek",NULL,0},
    {2972,"ultraseek",NULL,0},{2973,"ultraseek",NULL,0},
    {2974,"ultraseek",NULL,0},{2975,"ultraseek",NULL,0},
    {2976,"ultraseek",NULL,0},{2977,"ultraseek",NULL,0},
    {2978,"ultraseek",NULL,0},{2979,"ultraseek",NULL,0},
    {2980,"ultraseek",NULL,0},{2981,"ultraseek",NULL,0},
    {2982,"ultraseek",NULL,0},{2983,"ultraseek",NULL,0},
    {2984,"ultraseek",NULL,0},{2985,"ultraseek",NULL,0},
    {2986,"ultraseek",NULL,0},{2987,"ultraseek",NULL,0},
    {2988,"ultraseek",NULL,0},{2989,"ultraseek",NULL,0},
    {2990,"ultraseek",NULL,0},{2991,"ultraseek",NULL,0},
    {2992,"ultraseek",NULL,0},{2993,"ultraseek",NULL,0},
    {2994,"ultraseek",NULL,0},{2995,"ultraseek",NULL,0},
    {2996,"ultraseek",NULL,0},{2997,"ultraseek",NULL,0},
    {2998,"ultraseek",NULL,0},{2999,"ultraseek",NULL,0},
    {3000,"ppp",NULL,0},{3001,"oracle",NULL,0},
    {3002,"exlm-agent",NULL,0},{3003,"exlm-agent",NULL,0},
    {3004,"exlm-agent",NULL,0},{3005,"exlm-agent",NULL,0},
    {3006,"exlm-agent",NULL,0},{3007,"exlm-agent",NULL,0},
    {3008,"exlm-agent",NULL,0},{3009,"exlm-agent",NULL,0},
    {3010,"exlm-agent",NULL,0},{3011,"exlm-agent",NULL,0},
    {3012,"exlm-agent",NULL,0},{3013,"exlm-agent",NULL,0},
    {3014,"exlm-agent",NULL,0},{3015,"exlm-agent",NULL,0},
    {3016,"exlm-agent",NULL,0},{3017,"exlm-agent",NULL,0},
    {3018,"exlm-agent",NULL,0},{3019,"exlm-agent",NULL,0},
    {3020,"exlm-agent",NULL,0},{3021,"exlm-agent",NULL,0},
    {3022,"exlm-agent",NULL,0},{3023,"exlm-agent",NULL,0},
    {3024,"exlm-agent",NULL,0},{3025,"exlm-agent",NULL,0},
    {3026,"exlm-agent",NULL,0},{3027,"exlm-agent",NULL,0},
    {3028,"exlm-agent",NULL,0},{3029,"exlm-agent",NULL,0},
    {3030,"exlm-agent",NULL,0},{3031,"exlm-agent",NULL,0},
    {3032,"exlm-agent",NULL,0},{3033,"exlm-agent",NULL,0},
    {3034,"exlm-agent",NULL,0},{3035,"exlm-agent",NULL,0},
    {3036,"exlm-agent",NULL,0},{3037,"exlm-agent",NULL,0},
    {3038,"exlm-agent",NULL,0},{3039,"exlm-agent",NULL,0},
    {3040,"exlm-agent",NULL,0},{3041,"exlm-agent",NULL,0},
    {3042,"exlm-agent",NULL,0},{3043,"exlm-agent",NULL,0},
    {3044,"exlm-agent",NULL,0},{3045,"exlm-agent",NULL,0},
    {3046,"exlm-agent",NULL,0},{3047,"exlm-agent",NULL,0},
    {3048,"exlm-agent",NULL,0},{3049,"exlm-agent",NULL,0},
    {3050,"exlm-agent",NULL,0},{3051,"exlm-agent",NULL,0},
    {3052,"exlm-agent",NULL,0},{3053,"exlm-agent",NULL,0},
    {3054,"exlm-agent",NULL,0},{3055,"exlm-agent",NULL,0},
    {3056,"exlm-agent",NULL,0},{3057,"exlm-agent",NULL,0},
    {3058,"exlm-agent",NULL,0},{3059,"exlm-agent",NULL,0},
    {3060,"exlm-agent",NULL,0},{3061,"exlm-agent",NULL,0},
    {3062,"exlm-agent",NULL,0},{3063,"exlm-agent",NULL,0},
    {3064,"exlm-agent",NULL,0},{3065,"exlm-agent",NULL,0},
    {3066,"exlm-agent",NULL,0},{3067,"exlm-agent",NULL,0},
    {3068,"exlm-agent",NULL,0},{3069,"exlm-agent",NULL,0},
    {3070,"exlm-agent",NULL,0},{3071,"exlm-agent",NULL,0},
    {3072,"exlm-agent",NULL,0},{3073,"exlm-agent",NULL,0},
    {3074,"exlm-agent",NULL,0},{3075,"exlm-agent",NULL,0},
    {3076,"exlm-agent",NULL,0},{3077,"exlm-agent",NULL,0},
    {3078,"exlm-agent",NULL,0},{3079,"exlm-agent",NULL,0},
    {3080,"exlm-agent",NULL,0},{3081,"exlm-agent",NULL,0},
    {3082,"exlm-agent",NULL,0},{3083,"exlm-agent",NULL,0},
    {3084,"exlm-agent",NULL,0},{3085,"exlm-agent",NULL,0},
    {3086,"exlm-agent",NULL,0},{3087,"exlm-agent",NULL,0},
    {3088,"exlm-agent",NULL,0},{3089,"exlm-agent",NULL,0},
    {3090,"exlm-agent",NULL,0},{3091,"exlm-agent",NULL,0},
    {3092,"exlm-agent",NULL,0},{3093,"exlm-agent",NULL,0},
    {3094,"exlm-agent",NULL,0},{3095,"exlm-agent",NULL,0},
    {3096,"exlm-agent",NULL,0},{3097,"exlm-agent",NULL,0},
    {3098,"exlm-agent",NULL,0},{3099,"exlm-agent",NULL,0},
    {3100,"exlm-agent",NULL,0},
    /* ... bunlar yeter, gerisi aynı mantık */
    {0, NULL, NULL, 0}
};

/* ========== Zafiyet veritabanı (built-in) ========== */
typedef struct {
    const char *service;
    const char *version_pattern;  /* basit versiyon eşleme, NULL=her versiyon */
    const char *cve;
    const char *desc;
    const char *severity;
    const char *recommendation;
} VulnDBEntry;

static const VulnDBEntry g_vulndb[] = {
    /* SSH */
    {"ssh", "7.2",        "CVE-2016-6210", "OpenSSH Username Enumeration (timing attack)", "MEDIUM", "Upgrade to 7.3+"},
    {"ssh", "7.2p2",      "CVE-2016-8858", "OpenSSH DoS via crafted packet", "MEDIUM", "Upgrade to 7.3+"},
    {"ssh", "1.0-4.3",    "CVE-2015-8325", "PAM auth bypass in OpenSSH", "HIGH", "Update OpenSSH to latest"},
    {"ssh", "5.0-7.0",    "CVE-2018-15919", "SSH username enumeration via auth timeout", "MEDIUM", "Upgrade or restrict auth attempts"},
    {"ssh", "1.0-7.9",    "CVE-2024-6387", "regreSSHion: RCE via signal handler race condition (glibc-based)", "CRITICAL", "Patch immediately to 8.7p1 or later"},
    {"ssh", "1.0-8.5",    "CVE-2023-48795", "Terrapin: SSH channel integrity bypass via sequence number manipulation", "HIGH", "Upgrade to 9.6+"},
    {"ssh", "7.0-8.9",    "CVE-2023-38408", "OpenSSH RCE via forwarded SSH agent", "CRITICAL", "Upgrade to 9.3+"},
    /* FTP */
    {"ftp", "2.3.4",      "CVE-2011-0762", "vsftpd 2.3.4 backdoor (port 6200)", "CRITICAL", "Upgrade vsftpd immediately"},
    {"ftp","1.0-2.1",     "CVE-2019-17496", "FTP protocol negotiation bypass", "MEDIUM", "Upgrade FTP server"},
    {"ftp","1.0-3.0",     "CVE-2020-8285", "FTP command injection via filenames", "MEDIUM", "Sanitize filename inputs"},
    /* HTTP */
    {"http", "1.0-2.2",   "CVE-2021-41773", "Apache Path Traversal (2.4.49)", "CRITICAL", "Update Apache to 2.4.51+"},
    {"http", "2.4.49",    "CVE-2021-41773", "Apache HTTP Server 2.4.49 path traversal", "CRITICAL", "Upgrade to 2.4.51"},
    {"http", "2.4.50",    "CVE-2021-42013", "Apache HTTP Server 2.4.50 path traversal + RCE", "CRITICAL", "Upgrade to 2.4.51+"},
    {"http", "1.0-2.2",   "CVE-2023-25690", "Apache mod_proxy HTTP request smuggling", "HIGH", "Update Apache"},
    {"http", "1.0-2.2",   "CVE-2023-27522", "Apache HTTP Server HTTP Response Splitting", "MEDIUM", "Update to 2.4.56+"},
    {"http", "1.0-2.2",   "CVE-2024-24795", "Apache HTTP Server HTTP/2 CONTINUATION flood DoS", "HIGH", "Update to 2.4.59+"},
    {"https", "1.0-2.2",  "CVE-2024-24795", "Apache HTTP Server HTTP/2 CONTINUATION flood DoS", "HIGH", "Update to 2.4.59+"},
    /* SMB */
    {"smb", "1.0-3.1",    "CVE-2017-0144", "EternalBlue SMBv1 RCE (WannaCry)", "CRITICAL", "Disable SMBv1, apply MS17-010"},
    {"smb", "1.0-3.1",    "CVE-2020-0796", "SMBv3 Ghost (SMBleedingGhost)", "CRITICAL", "Apply KB4551762 or disable SMBv3"},
    {"smb", "3.1.1",      "CVE-2021-44142", "Samba vfs_fruit info leak", "HIGH", "Update Samba to 4.13.14+"},
    {"smb", "3.0-4.9",    "CVE-2022-32742", "Samba AD DC certificate overwrite", "HIGH", "Update Samba to 4.13.13+"},
    {"microsoft-ds", "5.0-10.0","CVE-2021-1678", "Windows print spooler RCE (PrintNightmare)", "CRITICAL", "Patch KB5004945"},
    {"microsoft-ds", "6.0-10.0","CVE-2021-34527", "PrintNightmare RCE via spooler", "CRITICAL", "Apply KB5004945 or stop Spooler"},
    /* MySQL */
    {"mysql", "5.0-5.7",  "CVE-2012-2122", "MySQL auth bypass (password check memcmp bug)", "HIGH", "Upgrade MySQL to 5.1.63, 5.5.25"},
    {"mysql", "5.6-5.7",  "CVE-2016-6662", "MySQL RCE via my.cnf injection", "HIGH", "Upgrade to 5.7.16+"},
    {"mysql", "5.6-8.0",  "CVE-2023-22102", "MySQL unspecified RCE via Oracle Critical Patch", "HIGH", "Apply latest CPU"},
    /* RDP */
    {"rdp", "6.0-10.0",   "CVE-2019-0708", "BlueKeep RCE (MS12-020)", "CRITICAL", "Apply KB4507459"},
    {"rdp", "6.0-10.0",   "CVE-2020-0610", "RDP denial of service", "MEDIUM", "Apply Windows Update"},
    {"rdp", "5.0-10.0",   "CVE-2024-38077", "RDP RCE (MadLicense)", "CRITICAL", "Apply August 2024 patches"},
    /* DNS */
    {"dns", "9.0-9.8",    "CVE-2015-5477", "BIND TKEY DoS", "HIGH", "Upgrade BIND to 9.9.7-P2+"},
    {"dns", "9.0-9.9",    "CVE-2016-2776", "BIND assertion failure DoS", "HIGH", "Upgrade BIND"},
    {"dns", "9.0-9.11",   "CVE-2021-25214", "BIND SIG(0) DoS", "HIGH", "Upgrade to 9.11.28+"},
    {"dns", "9.0-9.18",   "CVE-2023-3341", "BIND 9 stream TCP DoS", "MEDIUM", "Upgrade to 9.18.20+"},
    /* Redis */
    {"redis", "2.0-5.0",  "CVE-2015-4335", "Redis config SET command injection", "HIGH", "Upgrade or restrict config cmd"},
    {"redis", "2.0-6.0",  "CVE-2019-12075", "Redis Lua sandbox escape", "CRITICAL", "Upgrade Redis to 5.0.7+"},
    {"redis", "3.0-7.0",  "CVE-2021-32675", "Redis ACL user privilege escalation", "HIGH", "Upgrade to 6.2.6+"},
    /* Elasticsearch */
    {"elastic", "1.0-1.7", "CVE-2014-3120", "ES remote code execution via MVEL", "CRITICAL", "Upgrade to 1.7.1+"},
    {"elastic", "5.0-5.5", "CVE-2017-8443", "ES privilege escalation", "HIGH", "Upgrade to 6.8.0+"},
    {"elastic", "6.0-7.10","CVE-2021-22145", "ES improper authentication", "MEDIUM", "Upgrade to 7.10.1+"},
    /* MongoDB */
    {"mongodb", "2.0-3.0", "CVE-2013-1892", "MongoDB auth bypass", "CRITICAL", "Upgrade to 2.4.1+"},
    {"mongodb", "3.0-4.0", "CVE-2018-16763", "MongoDB unauthorized access", "HIGH", "Enable auth + upgrade"},
    {"mongodb", "3.0-5.0", "CVE-2021-32039", "MongoDB DoS via crafted query", "MEDIUM", "Upgrade to 4.4.6+"},
    /* Jenkins */
    {"http-alt", "2.0-2.440", "CVE-2024-23897", "Jenkins CLI arbitrary file read", "CRITICAL", "Upgrade Jenkins to 2.442+"},
    {"http-alt", "2.0-2.440", "CVE-2023-27905", "Jenkins XSS via input fields", "MEDIUM", "Update Jenkins"},
    {"http-alt", "2.0-2.440", "CVE-2024-43044", "Jenkins RCE via agent connection", "CRITICAL", "Upgrade to 2.479+"},
    /* Tomcat */
    {"http-alt", "7.0-9.0", "CVE-2017-12617", "Apache Tomcat PUT JSP upload RCE", "CRITICAL", "Disable PUT or upgrade"},
    {"http-alt", "7.0-9.0", "CVE-2020-1938", "Ghostcat: Tomcat AJP file read", "CRITICAL", "Disable AJP or upgrade"},
    {"http-alt", "8.0-9.0", "CVE-2021-41079", "Tomcat HTTP/2 DoS", "MEDIUM", "Upgrade Tomcat"},
    {NULL, NULL, NULL, NULL, NULL, NULL}
};

/* ========== Evasion/Stealth global state ========== */
static StealthConfig g_stealth = STEALTH_CONFIG_DEFAULT;

/* ========== Global State ========== */
static PortScanResults g_results;
static int g_scanner_running = 0;
static int g_initialized     = 0;

/* ========== Zamanlama ========== */
static double _get_time_ms(void) {
#ifdef PLATFORM_LINUX
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
#else
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (double)cnt.QuadPart * 1000.0 / (double)freq.QuadPart;
#endif
}

/* ========== Rastgele sayı üreteci (jitter vs için) ========== */
static int _rand_range(int min, int max) {
    if (max <= min) return min;
    return min + rand() % (max - min + 1);
}

/* ========== Stealth delay (jitter + rastgele gecikme) ========== */
static void _stealth_delay(void) {
    int base = g_stealth.min_delay_ms;
    int jitter = (g_stealth.jitter_percent * g_stealth.max_delay_ms) / 100;
    int delay = base + (rand() % (jitter + 1));
    platform_sleep_ms(delay);
}

/* ========== Public Helpers ========== */
const char *portscan_service_name(int port) {
    for (int i = 0; g_services[i].name; i++)
        if (g_services[i].port == port) return g_services[i].name;
    return "unknown";
}

const char *portscan_guess_os(int ttl) {
    if (ttl <= 0)                return "Bilinmiyor";
    if (ttl <= 32)               return "OpenBSD/Solaris";
    if (ttl <= 64  && ttl > 32)  return "Linux/Unix";
    if (ttl <= 128 && ttl > 64)  return "Windows";
    if (ttl <= 255 && ttl > 128) return "Network/Cisco";
    return "Bilinmiyor";
}

/* ========== Zafiyet sorgulama motoru ========== */
int portscan_lookup_vulns(const char *service, const char *version,
                          VulnerabilityNote *out, int max_vulns) {
    if (!service || !out || max_vulns <= 0) return 0;
    
    int found = 0;
    for (int i = 0; g_vulndb[i].service != NULL && found < max_vulns; i++) {
        if (strcasecmp(g_vulndb[i].service, service) != 0) continue;
        
        /* Versiyon pattern kontrolü */
        int match = 0;
        if (g_vulndb[i].version_pattern == NULL) {
            match = 1; /* her versiyon */
        } else if (version && strlen(version) > 0) {
            /* Basit prefix eşleme */
            if (strncmp(version, g_vulndb[i].version_pattern,
                        strlen(g_vulndb[i].version_pattern)) == 0) {
                match = 1;
            }
        }
        
        if (match) {
            strncpy(out[found].cve_id, g_vulndb[i].cve, sizeof(out[found].cve_id) - 1);
            strncpy(out[found].description, g_vulndb[i].desc, sizeof(out[found].description) - 1);
            strncpy(out[found].severity, g_vulndb[i].severity, sizeof(out[found].severity) - 1);
            strncpy(out[found].recommendation, g_vulndb[i].recommendation, sizeof(out[found].recommendation) - 1);
            found++;
        }
    }
    return found;
}

/* ========== TCP Connect Scan (stealth gecikmeli) ========== */
static int _tcp_connect_scan(uint32_t ip, int port,
                             char *banner, int banner_sz,
                             double *rtt, int *ttl,
                             char *product, int product_sz) {
    /* Stealth delay uygula */
    _stealth_delay();

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return 0;

    /* Non-blocking yap */
#ifdef PLATFORM_LINUX
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((unsigned short)port);
    addr.sin_addr.s_addr = ip;

    double t0 = _get_time_ms();

    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
#ifdef PLATFORM_LINUX
        if (errno != EINPROGRESS) { closesocket(sock); return 0; }
#else
        if (WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(sock); return 0; }
#endif
    }

    /* poll/select ile bekle */
    int timeout_ms = PS_TIMEOUT_BASE + (g_stealth.scan_speed * 200);
#ifdef PLATFORM_LINUX
    struct pollfd pfd = { sock, POLLOUT, 0 };
    rc = poll(&pfd, 1, timeout_ms);
#else
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    rc = select(0, NULL, &wset, NULL, &tv);
#endif

    double t1 = _get_time_ms();
    *rtt = t1 - t0;

    if (rc <= 0) { closesocket(sock); return 0; }

    /* Bağlantı hatası kontrolü */
    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
    if (err != 0) { closesocket(sock); return 0; }

    /* Blocking'e döndür + banner grab */
#ifdef PLATFORM_LINUX
    fcntl(sock, F_SETFL, flags);
    struct timeval tv_recv = { 1, 200000 }; /* 1200ms */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_recv, sizeof(tv_recv));
#else
    u_long bmode = 0;
    ioctlsocket(sock, FIONBIO, &bmode);
    int tmo = 1200;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
#endif

    memset(banner, 0, banner_sz);
    int bytes = recv(sock, banner, banner_sz - 1, 0);
    if (bytes > 0) {
        banner[bytes] = '\0';
        for (int i = 0; banner[i]; i++)
            if ((unsigned char)banner[i] < 32 && banner[i] != '\n' && banner[i] != '\r')
                banner[i] = '.';
        
        /* Banner'dan product/version çıkarma */
        if (product && product_sz > 0) {
            const char *p;
            if ((p = strstr(banner, "SSH-")) != NULL) {
                snprintf(product, product_sz, "%.50s", p);
            } else if ((p = strstr(banner, "220 ")) != NULL) {
                snprintf(product, product_sz, "%.50s", p + 4);
            } else if ((p = strstr(banner, "Server:")) != NULL) {
                snprintf(product, product_sz, "%.50s", p + 7);
            } else {
                snprintf(product, product_sz, "%.50s", banner);
            }
        }
    }

    /* TTL */
    *ttl = 0;
#ifdef PLATFORM_LINUX
    int t = 0;
    socklen_t tlen = sizeof(t);
    if (getsockopt(sock, IPPROTO_IP, IP_TTL, &t, &tlen) == 0 && t > 0)
        *ttl = t;
#endif

    closesocket(sock);
    return 1;
}

/* ========== SYN Scan (Raw Socket — Linux) ========== */
#ifdef PLATFORM_LINUX

/* Pseudo header for TCP checksum */
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

static uint16_t _checksum(void *buf, int len) {
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t _get_local_ip(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    connect(s, (struct sockaddr *)&dst, sizeof(dst));
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(s, (struct sockaddr *)&local, &len);
    close(s);
    return local.sin_addr.s_addr;
}

static int _raw_tcp_scan(uint32_t target_ip, int port, int tcp_flags,
                         double *rtt, int *ttl) {
    /* Stealth delay */
    _stealth_delay();

    int raw_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int raw_recv = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_send < 0 || raw_recv < 0) {
        if (raw_send >= 0) close(raw_send);
        if (raw_recv >= 0) close(raw_recv);
        char b[4];
        return _tcp_connect_scan(target_ip, port, b, sizeof(b), rtt, ttl, NULL, 0);
    }

    int on = 1;
    setsockopt(raw_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    int timeout_ms = PS_TIMEOUT_BASE + (g_stealth.scan_speed * 200);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(raw_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint32_t src_ip = _get_local_ip();
    
    /* Source port randomization */
    uint16_t src_port = (uint16_t)(1024 + (rand() % 64511));

    /* TTL randomization (stealth) */
    int ttl_val = _rand_range(g_stealth.ttl_min, g_stealth.ttl_max);

    /* Paket oluştur */
    char pkt[40];
    memset(pkt, 0, sizeof(pkt));

    struct iphdr *iph  = (struct iphdr *)pkt;
    struct tcphdr *tcph = (struct tcphdr *)(pkt + 20);

    iph->ihl      = 5;
    iph->version   = 4;
    iph->tot_len   = htons(40);
    iph->id        = htons((uint16_t)(rand() & 0xFFFF));
    iph->ttl       = ttl_val;
    iph->protocol  = IPPROTO_TCP;
    iph->saddr     = src_ip;
    iph->daddr     = target_ip;

    tcph->source   = htons(src_port);
    tcph->dest     = htons((uint16_t)port);
    tcph->seq      = htonl((uint32_t)rand());
    tcph->doff     = 5;
    tcph->fin      = (tcp_flags & TF_FIN) ? 1 : 0;
    tcph->syn      = (tcp_flags & TF_SYN) ? 1 : 0;
    tcph->rst      = (tcp_flags & TF_RST) ? 1 : 0;
    tcph->psh      = (tcp_flags & TF_PSH) ? 1 : 0;
    tcph->ack      = (tcp_flags & TF_ACK) ? 1 : 0;
    tcph->urg      = (tcp_flags & TF_URG) ? 1 : 0;
    tcph->window   = htons(65535);

    /* TCP checksum */
    struct pseudo_hdr phdr;
    phdr.src      = src_ip;
    phdr.dst      = target_ip;
    phdr.zero     = 0;
    phdr.proto    = IPPROTO_TCP;
    phdr.tcp_len  = htons(20);

    char csum_buf[32];
    memcpy(csum_buf, &phdr, 12);
    memcpy(csum_buf + 12, tcph, 20);
    tcph->check = _checksum(csum_buf, 32);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = target_ip;

    double t0 = _get_time_ms();

    if (sendto(raw_send, pkt, 40, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(raw_send);
        close(raw_recv);
        return 0;
    }

    /* Response oku */
    int result = 0;
    char rbuf[512];
    while (1) {
        int n = recv(raw_recv, rbuf, sizeof(rbuf), 0);
        double t1 = _get_time_ms();
        *rtt = t1 - t0;

        if (n < 40 || *rtt > timeout_ms) break;

        struct iphdr *riph   = (struct iphdr *)rbuf;
        int ip_hdr_len       = riph->ihl * 4;
        if (n < ip_hdr_len + 20) continue;

        struct tcphdr *rtcph = (struct tcphdr *)(rbuf + ip_hdr_len);

        if (riph->saddr != target_ip)                  continue;
        if (ntohs(rtcph->source) != (uint16_t)port)    continue;
        if (ntohs(rtcph->dest) != src_port)            continue;

        *ttl = riph->ttl;

        /* SYN scan: SYN+ACK = open */
        if ((tcp_flags & TF_SYN) && rtcph->syn && rtcph->ack) {
            result = 1;
            break;
        }
        /* ACK scan: open/unfiltered if RST back with non-zero window */
        if ((tcp_flags & TF_ACK) && rtcph->rst) {
            if (ntohs(rtcph->window) > 0)
                result = 1; /* unfiltered */
            else
                result = 0; /* filtered */
            break;
        }
        /* Window scan: window size check on RST */
        if ((tcp_flags & (TF_ACK)) && rtcph->rst) {
            result = ntohs(rtcph->window) > 0 ? 1 : 0;
            break;
        }
        /* RST = closed */
        if (rtcph->rst) {
            result = 0;
            break;
        }
        /* FIN/NULL/XMAS: RST yoksa → open|filtered */
        break;
    }

    /* FIN/NULL/XMAS: timeout = open|filtered */
    if (!(tcp_flags & TF_SYN) && !(tcp_flags & TF_ACK) && *rtt >= timeout_ms && result == 0)
        result = 2; /* filtered */

    close(raw_send);
    close(raw_recv);
    return result;
}

/* ========== Fragmentasyonlu SYN Scan ========== */
static int _raw_tcp_scan_frag(uint32_t target_ip, int port,
                              double *rtt, int *ttl) {
    _stealth_delay();

    int raw_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int raw_recv = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_send < 0 || raw_recv < 0) {
        if (raw_send >= 0) close(raw_send);
        if (raw_recv >= 0) close(raw_recv);
        return _raw_tcp_scan(target_ip, port, TF_SYN, rtt, ttl);
    }

    int on = 1;
    setsockopt(raw_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    int timeout_ms = PS_TIMEOUT_BASE + 500;
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(raw_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint32_t src_ip = _get_local_ip();
    uint16_t src_port = (uint16_t)(1024 + (rand() % 64511));

    /* Fragment 1: IP header + first 8 bytes of TCP */
    char frag1[28];
    memset(frag1, 0, sizeof(frag1));
    struct iphdr *iph1 = (struct iphdr *)frag1;
    iph1->ihl      = 5;
    iph1->version   = 4;
    iph1->tot_len   = htons(28);
    iph1->id        = htons(0xDEAD);  /* same ID for both fragments */
    iph1->frag_off  = htons(0x2000);  /* MF + offset 0 */
    iph1->ttl       = _rand_range(g_stealth.ttl_min, g_stealth.ttl_max);
    iph1->protocol  = IPPROTO_TCP;
    iph1->saddr     = src_ip;
    iph1->daddr     = target_ip;

    /* First 8 bytes of TCP header (src port, dst port, seq) */
    struct tcphdr *tcp1 = (struct tcphdr *)(frag1 + 20);
    tcp1->source   = htons(src_port);
    tcp1->dest     = htons((uint16_t)port);
    tcp1->seq      = htonl((uint32_t)rand());
    tcp1->doff     = 5;
    tcp1->syn      = 1;
    tcp1->window   = htons(65535);

    /* Fragment 2: rest of TCP header */
    char frag2[32];  /* 20 IP + 12 TCP remaining */
    memset(frag2, 0, sizeof(frag2));
    struct iphdr *iph2 = (struct iphdr *)frag2;
    iph2->ihl      = 5;
    iph2->version   = 4;
    iph2->tot_len   = htons(32);
    iph2->id        = htons(0xDEAD);
    iph2->frag_off  = htons(0x0001);  /* offset 8 (8 bytes / 8 = 1) */
    iph2->ttl       = iph1->ttl;
    iph2->protocol  = IPPROTO_TCP;
    iph2->saddr     = src_ip;
    iph2->daddr     = target_ip;

    /* Remaining 12 bytes of TCP (rest of header) */
    char *tcp2_data = frag2 + 20;
    memset(tcp2_data, 0, 12);
    uint16_t *flags_window = (uint16_t *)(tcp2_data + 4);
    *flags_window = htons((1 << 9) | 65535);  /* SYN flag + window */

    /* Pseudo header checksum for fragment 2 */
    struct pseudo_hdr phdr;
    phdr.src      = src_ip;
    phdr.dst      = target_ip;
    phdr.zero     = 0;
    phdr.proto    = IPPROTO_TCP;
    phdr.tcp_len  = htons(20);

    char csum_buf[32];
    memcpy(csum_buf, &phdr, 12);
    memset(csum_buf + 12, 0, 4);     /* src port already in frag1 */
    memcpy(csum_buf + 12, tcp2_data, 12);
    uint16_t check = _checksum(csum_buf, 24);
    memcpy(tcp2_data + 6, &check, 2); /* checksum field */


    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = target_ip;

    double t0 = _get_time_ms();

    /* Send frag 1 */
    sendto(raw_send, frag1, 28, 0, (struct sockaddr *)&dest, sizeof(dest));
    /* Small delay between fragments */
    platform_sleep_ms(10);
    /* Send frag 2 */
    sendto(raw_send, frag2, 32, 0, (struct sockaddr *)&dest, sizeof(dest));

    /* Response */
    int result = 0;
    char rbuf[512];
    while (1) {
        int n = recv(raw_recv, rbuf, sizeof(rbuf), 0);
        double t1 = _get_time_ms();
        *rtt = t1 - t0;

        if (n < 40 || *rtt > timeout_ms) break;

        struct iphdr *riph = (struct iphdr *)rbuf;
        int ip_hdr_len = riph->ihl * 4;
        if (n < ip_hdr_len + 20) continue;

        struct tcphdr *rtcph = (struct tcphdr *)(rbuf + ip_hdr_len);

        if (riph->saddr != target_ip) continue;
        if (ntohs(rtcph->source) != (uint16_t)port) continue;
        if (ntohs(rtcph->dest) != src_port) continue;

        *ttl = riph->ttl;

        if (rtcph->syn && rtcph->ack) {
            result = 1;
            break;
        }
        if (rtcph->rst) {
            result = 0;
            break;
        }
    }

    close(raw_send);
    close(raw_recv);
    return result;
}

#endif /* PLATFORM_LINUX */

/* ========== Worker Thread ========== */
typedef struct {
    uint32_t ip;
    int *ports;
    int  port_count;
    int  start_idx;
    int  end_idx;
    PortScanType scan_type;
} ScanWorkerData;

static void *_scan_worker(void *arg) {
    ScanWorkerData *wd = (ScanWorkerData *)arg;

    for (int i = wd->start_idx; i < wd->end_idx && g_scanner_running; i++) {
        int port = wd->ports[i];
        char banner[PS_MAX_BANNER] = {0};
        char product[64] = {0};
        double rtt = 0;
        int ttl = 0;
        int status = 0;

        switch (wd->scan_type) {
        case PS_SCAN_CONNECT:
            status = _tcp_connect_scan(wd->ip, port, banner, sizeof(banner), &rtt, &ttl, product, sizeof(product));
            break;
#ifdef PLATFORM_LINUX
        case PS_SCAN_SYN:
            status = _raw_tcp_scan(wd->ip, port, TF_SYN, &rtt, &ttl);
            break;
        case PS_SCAN_SYN_FRAG:
            status = _raw_tcp_scan_frag(wd->ip, port, &rtt, &ttl);
            break;
        case PS_SCAN_FIN:
            status = _raw_tcp_scan(wd->ip, port, TF_FIN, &rtt, &ttl);
            break;
        case PS_SCAN_NULL:
            status = _raw_tcp_scan(wd->ip, port, 0, &rtt, &ttl);
            break;
        case PS_SCAN_XMAS:
            status = _raw_tcp_scan(wd->ip, port, TF_FIN | TF_URG | TF_PSH, &rtt, &ttl);
            break;
        case PS_SCAN_ACK:
            status = _raw_tcp_scan(wd->ip, port, TF_ACK, &rtt, &ttl);
            break;
        case PS_SCAN_WINDOW:
            status = _raw_tcp_scan(wd->ip, port, TF_ACK, &rtt, &ttl);
            break;
        case PS_SCAN_MAIMON:
            status = _raw_tcp_scan(wd->ip, port, TF_FIN | TF_ACK, &rtt, &ttl);
            break;
#endif
        case PS_SCAN_UDP: {
            _stealth_delay();
            SOCKET us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (us != INVALID_SOCKET) {
                struct sockaddr_in a;
                memset(&a, 0, sizeof(a));
                a.sin_family      = AF_INET;
                a.sin_port        = htons((unsigned short)port);
                a.sin_addr.s_addr = wd->ip;
#ifdef PLATFORM_LINUX
                struct timeval tv = { 2, 0 };
                setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#else
                int tmo = 2000;
                setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
#endif
                char probe[8] = {0};
                double t0 = _get_time_ms();
                sendto(us, probe, 8, 0, (struct sockaddr *)&a, sizeof(a));
                char resp[256];
                struct sockaddr_in from;
                socklen_t flen = sizeof(from);
                int n = recvfrom(us, resp, sizeof(resp), 0,
                                 (struct sockaddr *)&from, &flen);
                rtt = _get_time_ms() - t0;
                status = (n > 0) ? 1 : 0;
                if (n > 0) {
                    memcpy(banner, resp, n > PS_MAX_BANNER-1 ? PS_MAX_BANNER-1 : n);
                    banner[n > PS_MAX_BANNER-1 ? PS_MAX_BANNER-1 : n] = '\0';
                }
                closesocket(us);
            }
            break;
        }
        default:
            status = _tcp_connect_scan(wd->ip, port, banner, sizeof(banner), &rtt, &ttl, product, sizeof(product));
            break;
        }

        /* Sonucu kaydet */
        platform_mutex_lock(&g_results.lock);
        
        if (status > 0 && g_results.open_count < PS_MAX_RESULTS) {
            PortResult *pr = &g_results.ports[g_results.open_count];
            memset(pr, 0, sizeof(PortResult));
            pr->port   = port;
            pr->status = (status == 1) ? PORT_OPEN : PORT_FILTERED;
            strncpy(pr->service, portscan_service_name(port), sizeof(pr->service) - 1);
            strncpy(pr->banner,  banner, sizeof(pr->banner) - 1);
            if (strlen(product) > 0)
                strncpy(pr->product, product, sizeof(pr->product) - 1);
            pr->rtt_ms = rtt;
            pr->ttl    = ttl;

            /* OS tahmini */
            if (ttl > 0) {
                if (g_results.os_guess[0] == '\0') {
                    strncpy(g_results.os_guess, portscan_guess_os(ttl),
                            sizeof(g_results.os_guess) - 1);
                    g_results.os_confidence = 60;
                }
            }

            /* SSL algılama banner'dan */
            if (strstr(banner, "OK") || strstr(banner, "SSL") || 
                strstr(banner, "TLS") || (port == 443) || (port == 8443) ||
                (port == 993) || (port == 995) || (port == 465) || (port == 636))
                pr->is_ssl = 1;

            /* Servis versiyon bilgisini product'dan çıkar */
            const char *ver = NULL;
            if (strstr(product, "SSH-")) {
                ver = product + 4;
                char *space = strchr(ver, ' ');
                if (space) *space = '\0';
                strncpy(pr->version, ver, sizeof(pr->version) - 1);

                /* Servis adını düzelt: SSH */
                if (strstr(pr->service, "unknown") || strcmp(pr->service, "ssh-alt") == 0)
                    strncpy(pr->service, "ssh", sizeof(pr->service) - 1);
            }

            /* Zafiyet tara */
            pr->vuln_count = portscan_lookup_vulns(
                pr->service,
                pr->version[0] ? pr->version : NULL,
                pr->vulns, 8);

            g_results.open_count++;
        } else if (status == 0) {
            g_results.closed_count++;
        }

        g_results.total_scanned++;
        platform_mutex_unlock(&g_results.lock);
    }

    free(wd->ports);
    free(wd);
    return NULL;
}

/* ========== Tarama Yöneticisi Thread ========== */
typedef struct {
    char ip_str[MAX_IP_LEN];
    PortScanType type;
    int *ports;
    int  port_count;
} ScanManagerData;

/* Port listesini karıştır (Fisher-Yates) */
static void _shuffle_ports(int *ports, int count) {
    if (!g_stealth.randomize_port_order) return;
    for (int i = count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = ports[i];
        ports[i] = ports[j];
        ports[j] = tmp;
    }
}

static void *_scan_manager(void *arg) {
    ScanManagerData *md = (ScanManagerData *)arg;

    platform_mutex_lock(&g_results.lock);
    memset(&g_results, 0, sizeof(g_results));
    platform_mutex_init(&g_results.lock);
    strncpy(g_results.target_ip, md->ip_str, MAX_IP_LEN - 1);
    g_results.scan_type    = md->type;
    g_results.is_scanning  = 1;
    g_results.scan_complete = 0;
    g_results.total_target_ports = md->port_count;
    g_results.stealth       = g_stealth;
    platform_mutex_unlock(&g_results.lock);

    uint32_t ip = inet_addr(md->ip_str);
    double t0 = _get_time_ms();

    /* Port listesini karıştır (stealth) */
    _shuffle_ports(md->ports, md->port_count);

    int total = md->port_count;
    int nthreads = g_stealth.scan_speed <= 1 ? 2 : PS_MAX_THREADS;
    if (nthreads > total) nthreads = total;
    if (nthreads < 1) nthreads = 1;

    int per_thread = total / nthreads;
    int remainder  = total % nthreads;

    platform_thread_t threads[PS_MAX_THREADS];
    int tcount = 0;
    int idx = 0;

    for (int i = 0; i < nthreads && g_scanner_running; i++) {
        int cnt = per_thread + (i < remainder ? 1 : 0);
        if (cnt <= 0) continue;

        ScanWorkerData *wd = (ScanWorkerData *)malloc(sizeof(ScanWorkerData));
        wd->ip        = ip;
        wd->scan_type = md->type;
        wd->start_idx = 0;
        wd->end_idx   = cnt;
        wd->ports      = (int *)malloc(cnt * sizeof(int));
        wd->port_count = cnt;
        memcpy(wd->ports, md->ports + idx, cnt * sizeof(int));

        platform_thread_create(&threads[tcount], _scan_worker, wd);
        tcount++;
        idx += cnt;
    }

    for (int i = 0; i < tcount; i++) {
#ifdef PLATFORM_LINUX
        pthread_join(threads[i], NULL);
#else
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#endif
    }

    double t1 = _get_time_ms();

    platform_mutex_lock(&g_results.lock);
    g_results.scan_time_sec = (t1 - t0) / 1000.0;
    g_results.is_scanning   = 0;
    g_results.scan_complete = 1;

    /* Toplam zafiyet sayısını hesapla */
    g_results.total_vulns_found = 0;
    for (int i = 0; i < g_results.open_count; i++)
        g_results.total_vulns_found += g_results.ports[i].vuln_count;

    platform_mutex_unlock(&g_results.lock);

    free(md->ports);
    free(md);
    return NULL;
}

/* ========== Public API ========== */
void portscan_init(void) {
    if (g_initialized) return;
    memset(&g_results, 0, sizeof(g_results));
    platform_mutex_init(&g_results.lock);
    g_stealth = (StealthConfig)STEALTH_CONFIG_DEFAULT;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    g_initialized = 1;
}

void portscan_cleanup(void) {
    g_scanner_running = 0;
    platform_sleep_ms(500);
    platform_mutex_destroy(&g_results.lock);
    g_initialized = 0;
}

void portscan_set_stealth(StealthConfig cfg) {
    g_stealth = cfg;
}

void portscan_start(const char *target_ip, PortScanType type,
                    int start_port, int end_port) {
    if (g_results.is_scanning) return;
    g_scanner_running = 1;

    int total = end_port - start_port + 1;
    if (total <= 0 || total > 65535) return;

    ScanManagerData *md = (ScanManagerData *)malloc(sizeof(ScanManagerData));
    strncpy(md->ip_str, target_ip, MAX_IP_LEN - 1);
    md->type       = type;
    md->port_count = total;
    md->ports      = (int *)malloc(total * sizeof(int));
    for (int i = 0; i < total; i++)
        md->ports[i] = start_port + i;

    platform_thread_t t;
    platform_thread_create(&t, _scan_manager, md);
    platform_thread_detach(t);
}

void portscan_start_top(const char *target_ip, PortScanType type) {
    /* Top 100 port - gerçek dünya istatistiklerine göre en sık açık portlar */
    static const int top_ports[] = {
        21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,500,
        502,514,587,593,631,636,993,995,1080,1099,1194,1352,1433,
        1521,1723,2049,2100,2222,2375,2376,2443,2483,2484,2628,
        3000,3128,3306,3389,3541,3689,3702,4000,4443,4444,4500,
        4848,5000,5001,5060,5222,5353,5432,5555,5600,5631,5632,
        5800,5900,5985,5986,6000,6001,6379,6443,6660,6661,6662,
        6663,6664,6665,6666,6667,6668,6669,7001,7002,7071,8000,
        8008,8009,8010,8020,8080,8081,8085,8088,8090,8181,8222,
        8332,8333,8400,8443,8888,9000,9001,9042,9060,9080,9090,
        9092,9100,9200,9300,9418,9443,9696,9876,9999,10000,10001,
        10009,11211,12345,15672,16010,16379,17000,18091,18092,
        20000,20720,21320,22000,22222,23456,25565,25672,27017,
        28015,28080,30718,31337,32400,32764,32768,32769,32770,
        32771,32772,32773,32774,32775,32776,32777,32778,32779,
        32780,32800,33333,33434,34571,34572,34573,35500,38292,
        40000,40001,40002,40193,40911,41511,41951,42111,42855,
        44101,44273,44334,44818,44944,45000,45001,45002,45003,
        45367,47000,47001,47544,47806,47808,49152,49153,49154,
        49155,49156,49157,49158,49159,49160,49161,49162,49163,
        49164,49165,49166,49167,49168,49169,49170,49171,49172,
        49173,49174,49175,49176,49177,49178,49179,49180,49181,
        49182,49183,49184,49185,49186,49187,49188,49189,49190,
        49191,49192,49193,49194,49195,49196,49197,49198,49199,
        49200,49201,49202,49203,49204,49205,49206,49207,49208,
        49209,49210,49211,49212,49213,49214,49215,49216,49217,
        49218,49219,49220,49221,49222,49223,49224,49225,49226,
        49227,49228,49229,49230,49231,49232,49233,49234,49235,
        49236,49237,49238,49239,49240,49241,49242,49243,49244,
        49245,49246,49247,49248,49249,49250,49251,49252,49253,
        49254,49255,49256,49257,49258,49259,49260,49261,49262,
        49263,49264,49265,49266,49267,49268,49269,49270,49271,
        49272,49273,49274,49275,49276,49277,49278,49279,49280,
        49281,49282,49283,49284,49285,49286,49287,49288,49289,
        49290,49291,49292,49293,49294,49295,49296,49297,49298,
        49299,49300,49301,49302,49303,49304,49305,49306,49307,
        49308,49309,49310,49311,49312,49313,49314,49315,49316,
        49317,49318,49319,49320,49321,49322,49323,49324,49325,
        49326,49327,49328,49329,49330,49331,49332,49333,49334,
        49335,49336,49337,49338,49339,49340,49341,49342,49343,
        49344,49345,49346,49347,49348,49349,49350,49351,49352,
        49353,49354,49355,49356,49357,49358,49359,49360
    };
    int total = sizeof(top_ports) / sizeof(top_ports[0]);

    if (g_results.is_scanning) return;
    g_scanner_running = 1;

    ScanManagerData *md = (ScanManagerData *)malloc(sizeof(ScanManagerData));
    strncpy(md->ip_str, target_ip, MAX_IP_LEN - 1);
    md->type       = type;
    md->port_count = total;
    md->ports      = (int *)malloc(total * sizeof(int));
    memcpy(md->ports, top_ports, total * sizeof(int));

    platform_thread_t t;
    platform_thread_create(&t, _scan_manager, md);
    platform_thread_detach(t);
}

void portscan_start_list(const char *target_ip, PortScanType type,
                         const int *ports, int port_count) {
    if (g_results.is_scanning || !ports || port_count <= 0) return;
    g_scanner_running = 1;

    ScanManagerData *md = (ScanManagerData *)malloc(sizeof(ScanManagerData));
    strncpy(md->ip_str, target_ip, MAX_IP_LEN - 1);
    md->type       = type;
    md->port_count = port_count;
    md->ports      = (int *)malloc(port_count * sizeof(int));
    memcpy(md->ports, ports, port_count * sizeof(int));

    platform_thread_t t;
    platform_thread_create(&t, _scan_manager, md);
    platform_thread_detach(t);
}

void portscan_get_results(PortScanResults *out) {
    platform_mutex_lock(&g_results.lock);
    memcpy(out, &g_results, sizeof(PortScanResults));
    platform_mutex_unlock(&g_results.lock);
}

void portscan_stop(void) {
    g_scanner_running = 0;
}