#!/bin/bash
# menu.sh V1.62.0 for Clearswift SEG >= 4.8
#
# Copyright (c) 2018 NetCon Unternehmensberatung GmbH
# https://www.netcon-consulting.com
#
# Authors:
# Uwe Sommer (u.sommer@netcon-consulting.com)
# Dr. Marc Dierksen (m.dierksen@netcon-consulting.com)
###################################################################################################
# Config tool for missing features on Clearswift Secure E-Mail Gateway.
# These settings will ease many advanced configuration tasks and highly improve spam detection.
# Everything is in this single dialog file, which should be run as root.
#
# Clearswift
# - Letsencrypt certificates via ACME installation and integration
# - install latest VMware Tools from VMware repo
# - custom LDAP schedule
# - easy extraction of address lists from last clearswift policy
# - custom firewall rules for SSH access with CIDR support
# - change Tomcat SSL certificate for web administration
# - SSH Key authentication for cs-admin
# - removed triple authentication for cs-admin when becoming root
# - reconfigure local DNS Resolver without forwarders and DNSSec support
# - editable DNS A record for mail.intern (mutiple IP destinations)
# - apply configuration in bash to activate customisations
# - aliases for quick log access and menu config (pflogs, menu)
# - sample custom commands for "run external command" content rule
# - automatic mail queue cleanup
# - automatic daily CS config backup via mail
# - Hybrid-Analysis Falcon and Palo Alto Networks WildFire sandbox integration
# - Import 'run external command' policy rules
# - Install external commands including corresponding policy rules
# - Generate base policy configuration
#
# Postfix settings
# - Postscreen weighted blacklists and bot detection for Postfix
# - Postscreen deep protocol inspection (optional)
# - Postfix verbose TLS logging
# - Postfix recipient verification via next transport hop
# - DANE support for Postfix (outbound)
# - outbound header rewriting (anonymising)
# - Loadbalancing for Postfix transport rules (multi destination transport)
# - custom individual outbound settings (override general main.cf options)
# - Postfix notifications for rejected, bounced or error mails
# - custom Postfix ESMTP settings (disable auth and DSN silently)
# - advanced smtpd recipient restrictions and whitelists
# - smtpd late reject to identify senders of rejected messages
# - Office365 IP-range whitelisting
#
# Rspamd
# - Rspamd installation and integration as milter
# - Master-slave cluster setup
# - feature toggles for greylisting, rejecting, Bayes-learning, detailed spam headers, detailed Rspamd history, URL reputation and phishing detection
# - integration of Heinlein Spamassassin rules with automatic daily updates
# - integration of Pyzor and Razor
# - automatic Rspamd updates
# - integration of Elasticsearch logging
#
# Changelog:
# - bugfix
#
###################################################################################################
VERSION_MENU="$(grep '^# menu.sh V' $0 | awk '{print $3}')"
DIALOG='dialog'
TXT_EDITOR='vim'
PF_CUSTOMISE='/opt/cs-gateway/scripts/deployment/postfix_customise'
CONFIG_PF='/opt/cs-gateway/scripts/deployment/netcon-postfix.sh' # linked in postfix_customise
CONFIG_FW='/opt/cs-gateway/custom/custom.rules'
CONFIG_INTERN='/var/named/intern.db'
CONFIG_BIND='/etc/named.conf'
CONFIG_AUTO_UPDATE='/etc/yum/yum-cron.conf'
CONFIG_AUTO_UPDATE_ALT='/etc/sysconfig/yum-cron'
CONFIG_LDAP='/var/cs-gateway/ldap/schedule.properties'
CONFIG_OPTIONS='/etc/rspamd/local.d/options.inc'
CONFIG_ACTIONS='/etc/rspamd/override.d/actions.conf'
CONFIG_HEADERS='/etc/rspamd/override.d/milter_headers.conf'
CONFIG_BAYES='/etc/rspamd/override.d/classifier-bayes.conf'
CONFIG_GREYLIST='/etc/rspamd/local.d/greylist.conf'
CONFIG_LOCAL='/etc/rspamd/rspamd.conf.local'
CONFIG_HISTORY='/etc/rspamd/local.d/history_redis.conf'
CONFIG_RSPAMD_REDIS='/etc/rspamd/local.d/redis.conf'
CONFIG_SPAMASSASSIN='/etc/rspamd/local.d/spamassassin.conf'
CONFIG_CONTROLLER='/etc/rspamd/local.d/worker-controller.inc'
CONFIG_REPUTATION='/etc/rspamd/local.d/url_reputation.conf'
CONFIG_PHISHING='/etc/rspamd/local.d/phishing.conf'
CONFIG_ELASTIC='/etc/rspamd/local.d/elastic.conf'
FILE_RULES='/etc/rspamd/local.d/spamassassin.rules'
MAP_ALIASES='/etc/aliases'
MAP_TRANSPORT='/etc/postfix-outbound/transport.map'
DIR_CERT="/var/lib/acme/live/$(hostname)"
DIR_COMMANDS='/opt/cs-gateway/scripts/netcon'
DIR_MAPS='/etc/postfix/maps'
DIR_ADDRLIST='/tmp/TMPaddresslist'
DIR_RULES='/tmp/TMPrules'
ESMTP_ACCESS="$DIR_MAPS/esmtp_access"
HELO_ACCESS="$DIR_MAPS/check_helo_access"
RECIPIENT_ACCESS="$DIR_MAPS/check_recipient_access"
SENDER_ACCESS="$DIR_MAPS/check_sender_access"
SENDER_REWRITE="$DIR_MAPS/sender_canonical_maps"
SENDER_ROUTING="$DIR_MAPS/relayhost_map"
WHITELIST_POSTFIX="$DIR_MAPS/check_client_access_ips"
WHITELIST_POSTSCREEN="$DIR_MAPS/check_postscreen_access_ips"
HEADER_REWRITE="$DIR_MAPS/smtp_header_checks"
WHITELIST_IP='/var/lib/rspamd/whitelist_sender_ip'
WHITELIST_DOMAIN='/var/lib/rspamd/whitelist_sender_domain'
WHITELIST_FROM='/var/lib/rspamd/whitelist_sender_from'
MAP_CLIENT='/etc/postfix-inbound/client.map'
MAP_OFFICE365='/etc/postfix-inbound/office365.map'
LIST_OFFICE365='40.92.0.0/15 40.107.0.0/16 52.100.0.0/14 104.47.0.0/17'
LOG_FILES='/var/log/cs-gateway/mail.'
LAST_CONFIG='/var/cs-gateway/deployments/lastAppliedConfiguration.xml'
PASSWORD_KEYSTORE='changeit'
PF_IN='/opt/cs-gateway/custom/postfix-inbound/main.cf'
PF_OUT='/opt/cs-gateway/custom/postfix-outbound/main.cf'
PF_INBOUND='/var/cs-gateway/pending/postfix/postfix-inbound'
PF_OUTBOUND='/var/cs-gateway/pending/postfix/postfix-outbound'
SSH_KEYS='/home/cs-admin/.ssh/authorized_keys'
BLACKLISTS='zen.spamhaus.org*3 b.barracudacentral.org*2 ix.dnsbl.manitu.net*2 bl.spameatingmonkey.net bl.spamcop.net list.dnswl.org=127.0.[0..255].0*-2 list.dnswl.org=127.0.[0..255].1*-3 list.dnswl.org=127.0.[0..255].[2..3]*-4'
FILE_PASSWORD='/tmp/TMPpassword'
EMAIL_DEFAULT='uwe@usommer.de'
LINK_GITHUB='https://raw.githubusercontent.com/netcon-consulting/cs-menu/master'
LINK_UPDATE="$LINK_GITHUB/menu.sh"
LINK_CONFIG="$LINK_GITHUB/configs/sample_config.bk"
LINK_TEMPLATE="$LINK_GITHUB/configs/template_config.xml"
CRON_STATS='/etc/cron.monthly/stats_report.sh'
SCRIPT_STATS='/root/send_report.sh'
CRON_ANOMALY='/etc/cron.d/anomaly_detect.sh'
SCRIPT_ANOMALY='/root/check_anomaly.sh'
CRON_CLEANUP='/etc/cron.daily/cleanup_mqueue.sh'
CRON_SENDER='/etc/cron.daily/sender_whitelist.sh'
CRON_BACKUP='/etc/cron.daily/email_backup.sh'
CRON_RULES='/etc/cron.daily/update_rules.sh'
CRON_UPDATE='/etc/cron.daily/update_rspamd.sh'
MD5_RSPAMD='7ba3f694eed8e0015bdf605f9618424b'
BACKUP_IN='/root/inbound-main.cf'
BACKUP_OUT='/root/outbound-main.cf'
APPLY_NEEDED=''
RSPAMD_SCRIPT='
H4sIAGNGr1wAA41WbW/aSBD+fP4VU2NFyUnGSav0Tqnoqdc4OVQCCMidTu0JGXsNFsZLdtdpo5D/
frO7XnsNKKo/GHvmmbdnZsd03gSLrAj4yuk4HWB8G20S8EGsMg48ZtlWABcRExyiIsFHuuWoJAaZ
RGRDC6fT6cCf4W1/CP1hf4a3mxF6GzP6mCWEX0F9aTPUTchDmTGS+FPpXSE8hr4EmaccvIKI75St
20C61Z6M1rJA4DVJozIXlkO4bInRHN+nK8qEf010cRktrmDSrgVaSn1VEHmHNMsFYVmxrCxgy2hM
OFcshMNrmwP0Fq/WMS3SbCl9+fD7JVzIvJJWkIpOJD3aD8KfuCAbtKjCFNGGXDVENr7xCoiIA62q
frpSfxSGfrUwqH1tswTjEo0KHiMWsLLY84cYR9JISxYTSMsiliVAni1YxJ66TrdKIu4mQVZkAn8M
iFuGVQtlgTqLkkUSUzto0jOzgMafVyRe4/xFwnaArJXbrvMVXG8Yzv4ZTb70h7cu9MAtqAv/wckJ
kB+ZgHPH0UX03KDkTA2+FrhaESWbfRWKXAeZX/a800XEiWQf505ZnTnOZDr+dHc9/zwa3sxv+oMQ
zY+3wDXQ+2k46blzE7eS3k5G92NLjMX46fE+6YIOWKqa6OQ0Xssm9lT/5FvAywXiaoQ6z6dn8OzI
NmOgH6YgdL3baa4ujTI1yqZIC/ZewUi8ouAX4Lnq8MmeeJKzK3CVvjonJoofg7dPHPhlLZQUgb+s
3xU5yhEj4jHKe94fddgqTU9rwCcPcK4ZErSMV+AZPox9yQqDdl4kGXRbc2HXQbfbgzrWWZ7LU6il
4M/Cyd2RvLL0MKMPcmsWjtmDCuJ6WP50NAhn/45DF97gwHI881HuHuDr5EgB7rdv5+/efb14f+vW
+jSrH6ez0XjWvwtH97PeZS39vkIOZFqWGjkWOreE2pGAreY4JKLk8wfZ6QUj0boF4DkhW7hoyXIi
WrG9Z+vtxW/ACS1Im4h2UkcJq+p3Z9mG0FIAYYwyoHFcMvw4gGBPsluCqk9Uta67cENx16Rlnj9p
ufpykU2EiwnR1UIlvOtacfab/KU/GFhq3GCq+JQy8kgYRCnuaZj2byUOFkStbFIIOCXdZRfuh/3h
DKaDMByfWV50OyyeLd1eM45x3QxqK/UWs9ZIsI06x62jUKnrM3R4NBhpbwq9aARK5VAYvB55yW71
gCbaOqdR8lPGTTUTZfTKuTMb5K9qIUzC2d+fBq2FgLFT2fb5XgZVOVLfJFNpPbPr7TyPrSlVmela
7Vq/6pxbiPlDE97I4GOQkMegwKmEtx9PLlRC+GXBdXDhQlY0NDYDYx/I5mtmtF4zHB8+1O04bm0W
92vWFVO7houzV9GS5tej/faKvWqWv+/FbuFhddL9kYj7QCwgMcXghvCr559lxkzML5bLXxtjNbae
e8+jJf5l8s7hWUeS5O+0251F5bFMdrrAnc2BRftLc7hVam8dwqPY+R/GuLfatAsAAA==
'
SENDER_SCRIPT='
H4sIADUMr1wAA7VVXXPiNhR9jn/FXYeu7SRGgYfOdANsGD42zADJELb74FCPwAJrYsteWSxNN/vf
K9kKMRR2207rGQYs6Z5zz9GROH2D5pShOc5CwziFjLCAcH8TUkEimolqFsKvterP1UvjVE53kvSJ
01UowF44UL+s/QJjIjoJg49MEM5IGBOWzQnHYs1W8CGe31wAI2KRMFd+snUkKFtVF0mcw7XXIkz4
OxhhvoAuJfxR8oMdVwP9+/pgrWMY3cHEb3e7k+Hgftq0kIhTNB3d4SDgJMtU45ZhDNv3U79zO+4P
PsglXzBHi8xdYUE2+AkFJI2SJ9mtyFCEM9FO04iSQEpZ0tVa9k8TVv09jiTOp5vBtKeI/O7tqD0Y
a7CIzhHPUhwHaGuXr/0LkhhTZpVK+5Pb0d8oXPIklpRSyyuZFveCqeY0mp7RRSsifOWAL/A8ImA7
8NU48cBdglkpeWHCDN6+hQUW++PPsOIkBTcB9w4s+32j+dBoF5YOZY9TBfvQcqpn9ns584AOzFnG
t1IjSpnuY685s1JTfHjzCG4frBKSBdbXZcLBps3aFdBG0x73z2sOql/B+Tl1IOWUCajY9KzufNuh
00wqFk2zYpNFmBzh+Wccsn6xFuAG8NBSbtZLAw01UHPM3Og/JJ1iVw4/P4NuIB9RfcaPAeXgpnKs
HF/TkCmQlnCCAxgOxr0rCBLjhC7BgzcFqBqVoFcgQsKMk5Nxe9Tz8+hvZRZLCqVWjMUitCuXF4AY
jknTtL3fzNm5Y6ILwNKkQh/2arNcXUYCsDIEyEcry5H4W0dfcFt7PaPKtoVqlAkpf0mNIGEEGtCw
d/ZfHlYeFyF8TbWp31SOTcNQe7EFBMqk9VEGO4xO7grIRxqTa35tYRvcz2B5m08zL7yZeXQw88R0
5pHezIuGxXt2n49Z2kjQT15snV1bx1W+huhaZkfnoy7da7V2he2Cul9+iLsFKLxQpdpLw8iX3Xcm
g7upSrS8pInaT6hcysQZ+mjvX0/6fKtNdSmYSF7qAnMBMWZ4JQfnT9q6AhhdyBXy8jk6H5iHSP7K
nvf//3LruHTb057f+TiZ9Ma5L4G80+H8p74ypTgOP+AFe52qokBmrITl6N04KrYc4EJoIknc9d7U
EZCX1r4j+Gjtf6yrMLKkqrx5O5qKiYPl/0aP3kFZuWHgF/+C7/T3wSwfKFbXCV/u36LfuV/+BNba
ePbkCAAA
'
###################################################################################################
TITLE_MAIN='NetCon Clearswift Configuration'
###################################################################################################
# get install confirmation for specified feature
# parameters:
# $1 - feature name
# return values:
# error code - 0 for install, 1 for cancel
confirm_install() {
    exec 3>&1
    $DIALOG --backtitle "Install features" --yesno "Install '$1'?" 0 40 2>&1 1>&3
    RET_CODE=$?
    exec 3>&-
    return $RET_CODE
}
# get re-install confirmation for specified feature
# parameters:
# $1 - feature name
# return values:
# error code - 0 for install, 1 for cancel
confirm_reinstall() {
    exec 3>&1
    $DIALOG --backtitle "Install features" --yesno "'$1' already installed. Reinstall?" 0 60 2>&1 1>&3
    RET_CODE=$?
    exec 3>&-
    return $RET_CODE
}
# pause and ask for keypress
# parameters:
# none
# return values:
# none
get_keypress() {
    echo
    read -p 'Press any key to continue.'
}
# show wait screen
# parameters:
# $1 - dialog back title
# return values:
# none
show_wait() {
	$DIALOG --backtitle "$1" --title '' --infobox 'Please wait...' 3 20
}
###################################################################################################
# Install Secion
###################################################################################################
# install EPEL repo
# parameters:
# none
# return values:
# none
install_epel() {
    if ! [ -f '/etc/yum.repos.d/epel.repo' ]; then
        echo 'Installing EPEL...'
        wget http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm -O /tmp/epel-release-6-8.noarch.rpm
        rpm -ivh /tmp/epel-release-6-8.noarch.rpm
    fi
}
# install Clearswift from Repo
# parameters:
# none
# return values:
# none
install_seg() {
    clear
    echo "installing Clearswift Secure Mailgateway 4.x"
    curl --get --remote-name http://repo.clearswift.net/rhel6/gw/os/x86_64/Packages/cs-email-repo-conf-3.6.3-1.x86_64.rpm
    rpm --import http://repo.clearswift.net/it-pub.key
    rpm -ivh cs-email-repo-conf-3.6.3-1.x86_64.rpm
    rm -rf /etc/yum.repos.d/cs-gw-rhel.repo /etc/yum.repos.d/cs-media.repo
    wget https://www.redhat.com/security/fd431d51.txt -O /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
    yum remove -y postfix rsyslog
    yum install -y cs-email --enablerepo=cs-*
    sed -i '/\/media\/os/d' /etc/fstab
    rm -rf /etc/yum.repos.d/rhel-media.repo
    su cs-admin
    init_cs
    get_keypress
}
# install Rspamd
# parameters:
# none
# return values:
# none
install_rspamd() {
    clear
    install_epel
    curl https://rspamd.com/rpm-stable/centos-6/rspamd.repo > /etc/yum.repos.d/rspamd.repo
    rpm --import https://rspamd.com/rpm-stable/gpg.key
    yum install -y redis rspamd
    rspamadm configwizard
    CONFIG_MULTIMAP='/etc/rspamd/local.d/multimap.conf'
    echo 'IP_WHITELIST {'$'\n\t''type = "ip";'$'\n\t''prefilter = "true";'$'\n\t'"map = \"$WHITELIST_IP\";"$'\n\t''action = "accept";'$'\n''}' > "$CONFIG_MULTIMAP"
    echo $'\n''WHITELIST_SENDER_DOMAIN {'$'\n\t''type = "from";'$'\n\t''filter = "email:domain";'$'\n\t'"map = \"$WHITELIST_DOMAIN\";"$'\n\t''score = -10.0;'$'\n''}' >> "$CONFIG_MULTIMAP"
    echo $'\n''SENDER_FROM_WHITELIST_USER {'$'\n\t''type = "from";'$'\n\t''filter = "email:addr";'$'\n\t'"map = \"$WHITELIST_FROM\";"$'\n\t''score = -10.0;'$'\n''}' >> "$CONFIG_MULTIMAP"
    echo 'extended_spam_headers = true;' > "$CONFIG_HEADERS"
    echo 'autolearn = true;' > "$CONFIG_BAYES"
    echo 'reject = null;' > "$CONFIG_ACTIONS"
    echo 'greylist = null;' >> "$CONFIG_ACTIONS"
    echo 'enabled = false;' > "$CONFIG_GREYLIST"
    echo 'servers = 127.0.0.1:6379;' > "$CONFIG_HISTORY"
    echo "ruleset = \"$FILE_RULES\";"$'\n''alpha = 0.1;' > "$CONFIG_SPAMASSASSIN"
    echo 'enabled = true;' > "$CONFIG_REPUTATION"
    echo 'phishtank_enabled = true;'$'\n''phishtank_map = "https://rspamd.com/phishtank/online-valid.json.zst";' > "$CONFIG_PHISHING"
    VERSION_RULES="$(dig txt 2.4.3.spamassassin.heinlein-support.de +short | tr -d '"')"
    if [ -z "$VERSION_RULES" ]; then
        echo 'Cannot determine SA rules version'
    else
        FILE_DOWNLOAD="$DIR_RULES/$VERSION_RULES.tgz"
        mkdir -p "$DIR_RULES"
        rm -f $DIR_RULES/*
        curl --silent "http://www.spamassassin.heinlein-support.de/$VERSION_RULES.tar.gz" --output "$FILE_DOWNLOAD"

        if ! [ -f "$FILE_DOWNLOAD" ]; then
            echo 'Cannot download SA rules'
        else
            tar -C "$DIR_RULES" -xzf "$FILE_DOWNLOAD"
            cat $DIR_RULES/*.cf > "$FILE_RULES"
        fi
    fi
    PACKED_SCRIPT='
    H4sIAAlQq1wAA0svyi8tUFAqzkzPSywpLUotVlKo5lIAAr3MvOSc0pRUjZKiStuSotJUa4WCosz8
    osySSltDa4WU0oKczOTEklTb3NSi9FRNBSUVH39nR594Z38/NxfPIP2c/OTEHL0UfYTJ8ekgu/SS
    8/PSlAhbYYBpZH5ZalFRZkoqblNruQCAjCEi0AAAAA==
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /etc/rspamd/local.d/groups.conf
    PACKED_SCRIPT='
    H4sIAK1Pq1wAA7WOPQ7CMAyF957CygEYkJgQAyegygabG0xiNU1QbKgK6t0JKmJn4G3vR3qfTEOX
    o8AOng1UmfZ4OljzcW+NxD5oHaxXm+03PZO4wlflnGplXCDXw0Ai6AmEfUK9FRJAj5xEQQNBOz1y
    AZdjxC4XVL4TXDgqFU4eEumYS2+Wj3mhsfu/0Vj8hWZuXk2fo04qAQAA
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /etc/rspamd/local.d/signatures_group.conf
    printf "%s" $RSPAMD_SCRIPT | base64 -d | gunzip > /etc/init.d/rspamd
    get_keypress
}
# install ACME Tool
# parameters:
# none
# return values:
# none
install_letsencrypt() {
    ## Firewall settings
    ## letsencrypt validate cert requests
    TMP_REPONSE="/tmp/TMPreponse"
    clear
    install_epel
    if ! [ -f "$CONFIG_FW" ] || ! grep -q '\-I INPUT 4 -i eth0 -p tcp --dport 80 -j ACCEPT' "$CONFIG_FW"; then
        echo '-I INPUT 4 -i eth0 -p tcp --dport 80 -j ACCEPT' >> "$CONFIG_FW"
        iptables -I INPUT 4 -i eth0 -p tcp --dport 80 -j ACCEPT
    fi
    yum-config-manager --add-repo https://copr.fedorainfracloud.org/coprs/hlandau/acmetool/repo/epel-6/hlandau-acmetool-epel-6.repo
    yum install -y acmetool
    echo '"acmetool-quickstart-choose-server": https://acme-v01.api.letsencrypt.org/directory' > "$TMP_REPONSE"
    echo '"acmetool-quickstart-choose-method": listen' >> "$TMP_REPONSE"
    acmetool quickstart --response-file "$TMP_REPONSE"
    acmetool want "$(hostname)"
    if [ $? = 0 ]; then
        # import cert and key into CS keystore
        mv -f /var/cs-gateway/keystore /var/cs-gateway/keystore.old
        cd /home/cs-admin
        openssl pkcs12 -export -name tomcat -in "$DIR_CERT/cert" -inkey "$DIR_CERT/privkey" -out keystore.p12 -passout "pass:$PASSWORD_KEYSTORE"
        keytool -importkeystore -destkeystore /var/cs-gateway/keystore -srckeystore keystore.p12 -srcstoretype pkcs12 -deststorepass "$PASSWORD_KEYSTORE" -srcstorepass "$PASSWORD_KEYSTORE"
        keytool -list -keystore /var/cs-gateway/keystore -storepass "$PASSWORD_KEYSTORE"
        cs-servicecontrol restart tomcat &>/dev/null
    fi
    get_keypress
}
# install Auto update
# parameters:
# none
# return values:
# none
install_auto_update() {
    clear
    install_epel
    sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/cs-rhel-mirror.repo
    yum install -y yum-cron
    /etc/init.d/yum-cron start
    get_keypress
}
# install VMware Tools
# parameters:
# none
# return values:
# none
install_vmware_tools() {
    clear
    echo '[vmware-tools]'$'\n''name=VMware Tools for Red Hat Enterprise Linux $releasever - $basearch'$'\n''baseurl=http://packages.vmware.com/tools/esx/latest/rhel6/$basearch'$'\n''enabled=1'$'\n''gpgcheck=1'$'\n''gpgkey=http://packages.vmware.com/tools/keys/VMWARE-PACKAGING-GPG-RSA-KEY.pub' > /etc/yum.repos.d/VMWare-Tools.repo
    yum install -y vmware-tools-esx-nox
    cp /etc/vmware-tools/init/vmware-tools-* /etc/init.d/
    get_keypress
}
# install local DNS resolver
# parameters:
# none
# return values:
# none
install_local_dns() {
    clear
    grep -q "dnssec-validation auto;" $CONFIG_BIND || sed -i '/include/a\ \ dnssec-validation auto;' $CONFIG_BIND
    grep -q "#include" $CONFIG_BIND || sed -i 's/include/#include/' $CONFIG_BIND
    grep -q "named.ca" $CONFIG_BIND || sed -i 's/db\.cache/named\.ca/' $CONFIG_BIND
    /etc/init.d/named restart
    get_keypress
}
# install zbar
# parameters:
# none
# return values:
# none
install_zbar() {
    clear
    install_epel
    yum install -y zbar
    get_keypress
}
###################################################################################################
# Check if installed
###################################################################################################
# check whether CS-SEG is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_seg() {
    service cs-services status &>/dev/null
    [ $? = 1 ] && return 1 || return 0
}
# check whether Rspamd is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_rspamd() {
    service rspamd status &>/dev/null
    [ $? = 1 ] && return 1 || return 0
}
# check whether ACME Tool is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_letsencrypt() {
    which acmetool &>/dev/null
    return $?
}
# check whether Auto update is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_auto_update() {
    [ -f /etc/init.d/yum-cron ]
    return $?
}
# check whether Auto update is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_vmware_tools() {
    which vmware-toolbox-cmd &>/dev/null
    return $?
}
# check whether local DNS resolver is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_local_dns() {
    RET_CODE=$(grep -q "dnssec-validation auto;" $CONFIG_BIND || grep -q "#include" $CONFIG_BIND || grep -q "named.ca" $CONFIG_BIND)
    return $RET_CODE
}
# check whether zbar is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_zbar() {
    which zbarimg &>/dev/null
    return $?
}
###################################################################################################
# print info for installed feature
# parameters:
# $1 - feature name
# $2 - feature explanation
# $3 - feature enable option in menu
# return values:
# none
show_note() {
    $DIALOG --clear --backtitle "Install features" --msgbox "Feature '$1' installed.\n\n$2" 0 0
}
# get confirmation for installing specified feature, install if confirmed and show explanation
# parameters:
# $1 - feature specifier
# $2 - feature label
# $3 - feature explanation
# return values:
# none
install_feature() {
    if check_installed_$1; then
        confirm_reinstall "$2"
    else
        confirm_install "$2"
    fi
    if [ $? = 0 ]; then
        install_$1
        [ -z "$3" ] || show_note "$2" "$3"
    fi
}
# select installation options from dialog menu
# parameters:
# none
# return values:
# none
dialog_install() {
    DIALOG_RSPAMD="Rspamd"
    DIALOG_LETSENCRYPT="ACME Tool"
    DIALOG_AUTO_UPDATE="Auto update"
    DIALOG_VMWARE_TOOLS="VMware Tools"
    DIALOG_LOCAL_DNS="Local DNS resolver"
    DIALOG_ZBAR="Zbar QR-code reader"
    EXPLANATION_RSPAMD="Implemented as a milter on Port 11332.\nThe webinterface runs on Port 11334 on localhost.\nYou will need a SSH Tunnel to access the Web interface.\nssh root@servername -L 11334:127.0.0.1:11334\n\nEnable corresponding feature in menu under 'Enable features->Rspamd'"
    EXPLANATION_LETSENCRYPT="Easy acquisition of Let's Encrypt certificates for TLS. It will autorenew the certificates via cronjob.\n\nEnable corresponding feature in menu under 'Enable features->Let's-Encrypt-Cert'"
    EXPLANATION_LOCAL_DNS="DNS forwarding disabled and local DNSSec resolver enabled for DANE validation.\n\nEnable corresponding feature in menu under 'Enable features->DANE'"
    while true; do
        DIALOG_RSPAMD_INSTALLED="$DIALOG_RSPAMD"
        DIALOG_LETSENCRYPT_INSTALLED="$DIALOG_LETSENCRYPT"
        DIALOG_AUTO_UPDATE_INSTALLED="$DIALOG_AUTO_UPDATE"
        DIALOG_VMWARE_TOOLS_INSTALLED="$DIALOG_VMWARE_TOOLS"
        DIALOG_LOCAL_DNS_INSTALLED="$DIALOG_LOCAL_DNS"
        DIALOG_ZBAR_INSTALLED="$DIALOG_ZBAR"
        check_installed_rspamd && DIALOG_RSPAMD_INSTALLED+=' (installed)'
        check_installed_letsencrypt && DIALOG_LETSENCRYPT_INSTALLED+=' (installed)'
        check_installed_auto_update && DIALOG_AUTO_UPDATE_INSTALLED+=' (installed)'
        check_installed_vmware_tools && DIALOG_VMWARE_TOOLS_INSTALLED+=' (installed)'
        check_installed_local_dns && DIALOG_LOCAL_DNS_INSTALLED+=' (installed)'
        check_installed_zbar && DIALOG_ZBAR_INSTALLED+=' (installed)'
        exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN"             \
                --cancel-label "Back" --ok-label "Apply"                        \
                --menu "Choose features to install" 0 0 0                       \
                "$DIALOG_LOCAL_DNS_INSTALLED" ""                                \
                "$DIALOG_VMWARE_TOOLS_INSTALLED" ""                             \
                "$DIALOG_RSPAMD_INSTALLED" ""                                   \
                "$DIALOG_LETSENCRYPT_INSTALLED" ""                              \
                "$DIALOG_AUTO_UPDATE_INSTALLED" ""                              \
                "$DIALOG_ZBAR_INSTALLED" ""                                     \
                2>&1 1>&3)"
            RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_RSPAMD_INSTALLED")
                    install_feature "rspamd" "$DIALOG_RSPAMD" "$EXPLANATION_RSPAMD";;
                "$DIALOG_LETSENCRYPT_INSTALLED")
                    install_feature "letsencrypt" "$DIALOG_LETSENCRYPT" "$EXPLANATION_LETSENCRYPT";;
                "$DIALOG_AUTO_UPDATE_INSTALLED")
                    install_feature "auto_update" "$DIALOG_AUTO_UPDATE";;
                "$DIALOG_VMWARE_TOOLS_INSTALLED")
                    install_feature "vmware_tools" "$DIALOG_VMWARE_TOOLS";;
                "$DIALOG_LOCAL_DNS_INSTALLED")
                    install_feature "local_dns" "$DIALOG_LOCAL_DNS" "$EXPLANATION_LOCAL_DNS";;
                "$DIALOG_ZBAR_INSTALLED")
                    install_feature "zbar" "$DIALOG_ZBAR";;
            esac
        else
            break
        fi
    done
}
###################################################################################################
# enable/disable features in Postfix custom config
###################################################################################################
# enable Rspamd
# parameters:
# none
# return values:
# none
enable_rspamd() {
    for OPTION in                                                  \
        'smtpd_milters=inet:127.0.0.1:11332, inet:127.0.0.1:19127' \
        "mydestination=$(hostname)"; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
    NEW_ALIASES=''
    if ! grep -q 'learnspam: "| rspamc learn_spam"' $MAP_ALIASES; then
        echo 'learnspam: "| rspamc learn_spam"' >> $MAP_ALIASES
        NEW_ALIASES=1
    fi
    if ! grep -q 'learnham: "| rspamc learn_ham"' $MAP_ALIASES; then
        echo 'learnham: "| rspamc learn_ham"' >> $MAP_ALIASES
        NEW_ALIASES=1
    fi
    [ "$NEW_ALIASES" = 1 ] && newaliases
    echo "# start managed by $TITLE_MAIN" >> $WHITELIST_IP
    if [ -f "$MAP_CLIENT" ]; then
        CLIENT_REJECT="$(postmulti -i postfix-inbound -x postconf -n | grep '^cp_client_' | grep 'REJECT' | awk '{print $1}')"
        if [ -z "$CLIENT_REJECT" ]; then
            LIST_IP="$(awk '{print $1}' $MAP_CLIENT | sort -u | xargs)"
        else
            LIST_IP="$(awk "\$2 != \"$CLIENT_REJECT\" {print \$1}" $MAP_CLIENT | sort -u | xargs)"
        fi
        LIST_IPADDR=''
        for IP_ADDR in $LIST_IP; do
            NUM_DOTS="$(echo "$IP_ADDR" | awk -F. '{print NF-1}')"
            if [ "$NUM_DOTS" = 3 ]; then
                [ -z "$LIST_IPADDR" ] && LIST_IPADDR+="$IP_ADDR" || LIST_IPADDR+=" $IP_ADDR"
            elif [ "$NUM_DOTS" = 2 ]; then
                [ -z "$LIST_IPADDR" ] && LIST_IPADDR+="$IP_ADDR.0/24" || LIST_IPADDR+=" $IP_ADDR.0/24"
            elif [ "$NUM_DOTS" = 1 ]; then
                [ -z "$LIST_IPADDR" ] && LIST_IPADDR+="$IP_ADDR.0.0/16" || LIST_IPADDR+=" $IP_ADDR.0.0/16"
            else
                [ -z "$LIST_IPADDR" ] && LIST_IPADDR+="$IP_ADDR.0.0.0/8" || LIST_IPADDR+=" $IP_ADDR.0.0.0/8"
            fi
        done
        echo "$LIST_IPADDR" | xargs -n 1 >> $WHITELIST_IP
        echo "local_addrs = [$(echo "$LIST_IPADDR" | sed 's/ /, /g')];" >> $CONFIG_OPTIONS
    fi
    echo "# end managed by $TITLE_MAIN" >> $WHITELIST_IP
    chown _rspamd:_rspamd $WHITELIST_IP
    chkconfig rspamd on
    chkconfig redis on
    service redis start &>/dev/null
    service rspamd start &>/dev/null
}
# disable Rspamd
# parameters:
# none
# return values:
# none
disable_rspamd() {
    for OPTION in                                                  \
        'smtpd_milters=inet:127.0.0.1:11332, inet:127.0.0.1:19127' \
        "mydestination=$(hostname)"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
    if grep -q 'learnspam: "| rspamc learn_spam"' $MAP_ALIASES || grep -q 'learnham: "| rspamc learn_ham"' $MAP_ALIASES; then
        sed -i '/^learnspam: "| rspamc learn_spam"$/d' $MAP_ALIASES
        sed -i '/^learnham: "| rspamc learn_ham"$/d' $MAP_ALIASES
        newaliases
    fi
    [ -f "$WHITELIST_IP" ] && sed -i "/# start managed by $TITLE_MAIN/,/# end managed by $TITLE_MAIN/d" $WHITELIST_IP
    [ -f "$CONFIG_OPTIONS" ] && sed -i '/local_addrs = \[192.168.0.0\/16, 10.0.0.0\/8, 172.16.0.0\/12, fd00::\/8, 169.254.0.0\/16, fe80::\/10/d' $CONFIG_OPTIONS
    chkconfig rspamd off
    chkconfig redis off
    service rspamd stop &>/dev/null
    service redis stop &>/dev/null
}
# enable Let's Encrypt cert
# parameters:
# none
# return values:
# none
enable_letsencrypt() {
    if [ -f "$DIR_CERT/privkey" ] && [ -f "$DIR_CERT/fullchain" ]; then
        for OPTION in                                       \
            "smtpd_tls_key_file=$DIR_CERT/privkey"          \
            "smtpd_tls_cert_file=$DIR_CERT/fullchain"; do
            if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
                echo "$OPTION" >> "$PF_IN"
            fi
            postmulti -i postfix-inbound -x postconf "$OPTION"
        done
        for OPTION in                                       \
            "smtp_tls_key_file=$DIR_CERT/privkey"          \
            "smtp_tls_cert_file=$DIR_CERT/fullchain"; do
            if ! [ -f "$PF_OUT" ] || ! grep -q "$OPTION" "$PF_OUT"; then
                echo "$OPTION" >> "$PF_OUT"
            fi
            postmulti -i postfix-outbound -x postconf "$OPTION"
        done
    else
        $DIALOG --clear --backtitle "Enable features" --msgbox "Let's Encrypt certificates are missing." 0 0
    fi
}
# disable Let's Encrypt cert
# parameters:
# none
# return values:
# none
disable_letsencrypt() {
    for OPTION in                                       \
        "smtpd_tls_key_file=$DIR_CERT/privkey"          \
        "smtpd_tls_cert_file=$DIR_CERT/fullchain"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
    for OPTION in                                       \
        "smtp_tls_key_file=$DIR_CERT/privkey"          \
        "smtp_tls_cert_file=$DIR_CERT/fullchain"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_OUT"
    done    
}
# enable verbose TLS
# parameters:
# none
# return values:
# none
enable_tls() {
    [ -f /etc/postfix/dh1024.pem ] || openssl dhparam -out /etc/postfix/dh1024.pem 1024 &>/dev/null
    for OPTION in                                                  \
        'smtpd_tls_loglevel=1'                                     \
        'smtpd_tls_dh1024_param_file=/etc/postfix/dh1024.pem'; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
    for OPTION in                                                   \
        'smtp_tls_note_starttls_offer=yes'                          \
        'smtp_tls_loglevel=1'; do
        if ! [ -f "$PF_OUT" ] || ! grep -q "$OPTION" "$PF_OUT"; then
            echo "$OPTION" >> "$PF_OUT"
        fi        
        postmulti -i postfix-outbound -x postconf "$OPTION"
    done
}
# disable verbose TLS
# parameters:
# none
# return values:
# none
disable_tls() {
    for OPTION in                                                  \
        'smtpd_tls_loglevel=1'                                     \
        'smtpd_tls_dh1024_param_file=/etc/postfix/dh1024.pem'; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
    for OPTION in                                                   \
        'smtp_tls_note_starttls_offer=yes'                          \
        'smtp_tls_loglevel=1'; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_OUT"
    done
}
# enable ESMTP filter
# parameters:
# none
# return values:
# none
enable_esmtp_filter() {
    for OPTION in                                                               \
        "smtpd_discard_ehlo_keyword_address_maps=cidr:$ESMTP_ACCESS"   \
        'smtpd_discard_ehlo_keywords='; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
}
# disable ESMTP filter
# parameters:
# none
# return values:
# none
disable_esmtp_filter() {
    for OPTION in                                                               \
        "smtpd_discard_ehlo_keyword_address_maps=cidr:$ESMTP_ACCESS"   \
        'smtpd_discard_ehlo_keywords='; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
}
# enable DANE
# parameters:
# none
# return values:
# none
enable_dane() {
    for OPTION in                                                  \
        'smtp_tls_security_level=dane'                             \
        'smtp_dns_support_level=dnssec'; do
        if ! [ -f "$PF_OUT" ] || ! grep -q "$OPTION" "$PF_OUT"; then
            echo "$OPTION" >> "$PF_OUT"
        fi
        postmulti -i postfix-outbound -x postconf "$OPTION"
    done
}
# disable DANE
# parameters:
# none
# return values:
# none
disable_dane() {
    for OPTION in                                                  \
        'smtp_tls_security_level=dane'                             \
        'smtp_dns_support_level=dnssec'; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_OUT"
    done
}
# enable sender rewrite
# parameters:
# none
# return values:
# none
enable_sender_rewrite() {
    for OPTION in                                                             \
        "sender_canonical_maps=regexp:$SENDER_REWRITE"; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
}
# disable sender rewrite
# parameters:
# none
# return values:
# none
disable_sender_rewrite() {
    for OPTION in                                                             \
        "sender_canonical_maps=regexp:$SENDER_REWRITE"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
}
# enable sender dependent routing
# parameters:
# none
# return values:
# none
enable_sender_routing() {
    for OPTION in                                                             \
        "sender_dependent_default_transport_maps=hash:$SENDER_ROUTING"; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
}
# disable sender dependent routing
# parameters:
# none
# return values:
# none
disable_sender_routing() {
    for OPTION in                                                             \
        "sender_dependent_default_transport_maps=hash:$SENDER_ROUTING"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
}
# enable inbound bounce notification
# parameters:
# $1 - notification email address
# return values:
# error code - 0 for enabled, 1 for cancelled
enable_bounce_in() {
    local DIALOG_RET RET_CODE EMAIL_BOUNCE OPTION

    if [ -z "$1" ]; then
        exec 3>&1
        DIALOG_RET="$(dialog --clear --backtitle 'Enable features' --title 'Inbound bounce notifications'   \
            --inputbox 'Enter email for inbound bounce notifications' 0 50 $EMAIL_DEFAULT 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
            EMAIL_BOUNCE="$DIALOG_RET"
        else
            return 1
        fi
    else
        EMAIL_BOUNCE="$1"
    fi
    for OPTION in                                                                           \
        'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce'       \
        "2bounce_notice_recipient=$EMAIL_BOUNCE"                                            \
        "bounce_notice_recipient=$EMAIL_BOUNCE"                                             \
        "delay_notice_recipient=$EMAIL_BOUNCE"                                              \
        "error_notice_recipient=$EMAIL_BOUNCE"; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
}
# disable inbound bounce notification
# parameters:
# $1 - notification email address
# return values:
# none
disable_bounce_in() {
    for OPTION in                                                                           \
        'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce'       \
        "2bounce_notice_recipient=$EMAIL_BOUNCE"                                            \
        "bounce_notice_recipient=$EMAIL_BOUNCE"                                             \
        "delay_notice_recipient=$EMAIL_BOUNCE"                                              \
        "error_notice_recipient=$EMAIL_BOUNCE"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
}
# enable outbound bounce notification
# parameters:
# $1 - notification email address
# return values:
# error code - 0 for enabled, 1 for cancelled
enable_bounce_out() {
    local DIALOG_RET RET_CODE EMAIL_BOUNCE OPTION

    if [ -z "$1" ]; then
        exec 3>&1
        DIALOG_RET="$(dialog --clear --backtitle 'Enable features' --title 'Outbound bounce notifications'  \
            --inputbox 'Enter email for outbound bounce notifications' 0 50 $EMAIL_DEFAULT 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
            EMAIL_BOUNCE="$DIALOG_RET"
        else
            return 1
        fi
    else
        EMAIL_BOUNCE="$1"
    fi
    for OPTION in                                                                       \
        'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce'   \
        "2bounce_notice_recipient=$EMAIL_BOUNCE"                                        \
        "bounce_notice_recipient=$EMAIL_BOUNCE"                                         \
        "delay_notice_recipient=$EMAIL_BOUNCE"                                          \
        "error_notice_recipient=$EMAIL_BOUNCE"; do
        if ! [ -f "$PF_OUT" ] || ! grep -q "$OPTION" "$PF_OUT"; then
            echo "$OPTION" >> "$PF_OUT"
        fi
        postmulti -i postfix-outbound -x postconf "$OPTION"
    done
}
# disable outbound bounce notification
# parameters:
# $1 - notification email address
# return values:
# none
disable_bounce_out() {
    for OPTION in                                                                       \
        'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce'   \
        "2bounce_notice_recipient=$EMAIL_BOUNCE"                                        \
        "bounce_notice_recipient=$EMAIL_BOUNCE"                                         \
        "delay_notice_recipient=$EMAIL_BOUNCE"                                          \
        "error_notice_recipient=$EMAIL_BOUNCE"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_OUT"
    done
}
# enable Office365 IP range whitelisting
# parameters:
# none
# return values:
# none
enable_office365() {
    rm -f "$MAP_OFFICE365"
    for IP_ADDR in $LIST_OFFICE365; do
        echo "$IP_ADDR PERMIT" >> "$MAP_OFFICE365"
    done

    RELAY_RESTRICTIONS="$(postmulti -i postfix-inbound -x postconf smtpd_relay_restrictions | awk -F ' = ' '{print $2}')"
    for OPTION in                                                                                       \
        "smtpd_relay_restrictions=check_client_access cidr:$MAP_OFFICE365, $RELAY_RESTRICTIONS"; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
}
# disable Office365 IP range whitelisting
# parameters:
# none
# return values:
# none
disable_office365() {
    for OPTION in                                                                   \
        "smtpd_relay_restrictions=check_client_access cidr:$MAP_OFFICE365, "; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
}
# enable Postscreen
# parameters:
# none
# return values:
# none
enable_postscreen() {
    for OPTION in                                                                                                           \
        "postconf -c $PF_INBOUND -M# '25/inet'"                                                                             \
        "postconf -c $PF_INBOUND -Me '25/inet=25  inet n - n - 1 postscreen'"                                               \
        "postconf -c $PF_INBOUND -Me 'smtpd/pass=smtpd      pass  -       -       n       -       -       smtpd'"           \
        "postconf -c $PF_INBOUND -Me 'dnsblog/unix=dnsblog    unix  -       -       n       -       0       dnsblog'"       \
        "postconf -c $PF_INBOUND -Me 'tlsproxy/unix=tlsproxy   unix  -       -       n       -       0       tlsproxy'"     \
        "postconf -c $PF_INBOUND -e 'postscreen_access_list=permit_mynetworks cidr:$WHITELIST_POSTSCREEN'"                  \
        "postconf -c $PF_INBOUND -e 'postscreen_blacklist_action=enforce'"                                                  \
        "postconf -c $PF_INBOUND -e 'postscreen_command_time_limit=\${stress?10}\${stress:300}s'"                           \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_action=enforce'"                                                      \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_sites=$BLACKLISTS'"                                                   \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_threshold=3'"                                                         \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_ttl=1h'"                                                              \
        "postconf -c $PF_INBOUND -e 'postscreen_greet_action=enforce'"                                                      \
        "postconf -c $PF_INBOUND -e 'postscreen_greet_wait=\${stress?4}\${stress:15}s'"; do
        if ! [ -f "$CONFIG_PF" ] || ! grep -q "$OPTION" "$CONFIG_PF"; then
            echo "$OPTION" >> "$CONFIG_PF"
        fi
    done
}
# disable Postscreen
# parameters:
# none
# return values:
# none
disable_postscreen() {
    for OPTION in                                                                                                                               \
        "postconf -c $PF_INBOUND -M# '25/inet'"                                                                                                 \
        "postconf -c $PF_INBOUND -Me '25/inet=25  inet n - n - 1 postscreen'"                                                                   \
        "postconf -c $PF_INBOUND -Me 'smtpd/pass=smtpd      pass  -       -       n       -       -       smtpd'"                               \
        "postconf -c $PF_INBOUND -Me 'dnsblog/unix=dnsblog    unix  -       -       n       -       0       dnsblog'"                           \
        "postconf -c $PF_INBOUND -Me 'tlsproxy/unix=tlsproxy   unix  -       -       n       -       0       tlsproxy'"                         \
        "postconf -c $PF_INBOUND -e 'postscreen_access_list=permit_mynetworks cidr:$WHITELIST_POSTSCREEN'"                                      \
        "postconf -c $PF_INBOUND -e 'postscreen_blacklist_action=enforce'"                                                                      \
        "postconf -c $PF_INBOUND -e 'postscreen_command_time_limit=\${stress?10}\${stress:300}s'"                                               \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_action=enforce'"                                                                          \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_sites=$(echo $BLACKLISTS | sed 's/\[/\\\[/g' | sed 's/\]/\\\]/g' | sed 's/\*/\\\*/g')'"   \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_threshold=3'"                                                                             \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_ttl=1h'"                                                                                  \
        "postconf -c $PF_INBOUND -e 'postscreen_greet_action=enforce'"                                                                          \
        "postconf -c $PF_INBOUND -e 'postscreen_greet_wait=\${stress?4}\${stress:15}s'"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$CONFIG_PF"
    done
}
# enable Postscreen Deep inspection
# parameters:
# none
# return values:
# none
enable_postscreen_deep() {
    for OPTION in                                                                   \
        "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_enable=yes'"           \
        "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_action=enforce'"       \
        "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_action=enforce'"   \
        "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_enable=yes'"       \
        "postconf -c $PF_INBOUND -e 'postscreen_pipelining_enable=yes'"             \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_whitelist_threshold=-1'"; do
        if ! [ -f "$CONFIG_PF" ] || ! grep -q "$OPTION" "$CONFIG_PF"; then
            echo "$OPTION" >> "$CONFIG_PF"
        fi
    done

}
# disable Postscreen Deep inspection
# parameters:
# none
# return values:
# none
disable_postscreen_deep() {
    for OPTION in                                                                   \
        "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_enable=yes'"           \
        "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_action=enforce'"       \
        "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_action=enforce'"   \
        "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_enable=yes'"       \
        "postconf -c $PF_INBOUND -e 'postscreen_pipelining_enable=yes'"             \
        "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_whitelist_threshold=-1'"; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$CONFIG_PF"
    done

}
###################################################################################################
# check whether feature is already enabled
###################################################################################################
# check whether Rspamd is enabled
# parameters:
# none
# return values:
# Rspamd status
check_enabled_rspamd() {
    if [ -f "$PF_IN" ]                                                                  \
        && grep -q 'smtpd_milters=inet:127.0.0.1:11332, inet:127.0.0.1:19127' "$PF_IN"  \
        && grep -q "mydestination=$(hostname)" "$PF_IN"                                 \
        && grep -q 'learnspam: "| rspamc learn_spam"' "$MAP_ALIASES"                    \
        && grep -q 'learnham: "| rspamc learn_ham"' "$MAP_ALIASES"; then
        echo on
    else
        echo off
    fi
}
# check whether Let's Encrypt cert is enabled
# parameters:
# none
# return values:
# Let's Encrypt cert status
check_enabled_letsencrypt() {
    if [ -f "$PF_IN" ]                                                          \
        && grep -q "smtpd_tls_key_file=$DIR_CERT/privkey" "$PF_IN"              \
        && grep -q "smtpd_tls_cert_file=$DIR_CERT/fullchain" "$PF_IN"           \
        && [ -f "$PF_OUT" ]                                                     \
        && grep -q "smtp_tls_key_file=$DIR_CERT/privkey" "$PF_OUT"              \
        && grep -q "smtp_tls_cert_file=$DIR_CERT/fullchain" "$PF_OUT"; then
        echo on
    else
        echo off
    fi
}
# check whether verbose TLS is enabled
# parameters:
# none
# return values:
# verbose TLS status
check_enabled_tls() {
    if [ -f "$PF_IN" ]                                                              \
        && grep -q 'smtpd_tls_loglevel=1' "$PF_IN"                                  \
        && grep -q 'smtpd_tls_dh1024_param_file=/etc/postfix/dh1024.pem' "$PF_IN"   \
        && [ -f "$PF_OUT" ]                                                         \
        && grep -q 'smtp_tls_note_starttls_offer=yes' "$PF_OUT"                     \
        && grep -q 'smtp_tls_loglevel=1' "$PF_OUT"; then
        echo on
    else
        echo off
    fi
}
# check whether ESMTP filter is enabled
# parameters:
# none
# return values:
# ESMTP filter status
check_enabled_esmtp_filter() {
    if [ -f "$PF_IN" ]                                                                     \
        && grep -q "smtpd_discard_ehlo_keyword_address_maps=cidr:$ESMTP_ACCESS" "$PF_IN"   \
        && grep -q 'smtpd_discard_ehlo_keywords=' "$PF_IN"; then 
        echo on
    else
        echo off
    fi
}
# check whether DANE is enabled
# parameters:
# none
# return values:
# DANE status
check_enabled_dane() {
    if [ -f "$PF_OUT" ]                                             \
        && grep -q 'smtp_tls_security_level=dane' "$PF_OUT"         \
        && grep -q 'smtp_dns_support_level=dnssec' "$PF_OUT"; then
        echo on
    else
        echo off
    fi
}
# check whether sender rewrite is enabled
# parameters:
# none
# return values:
# sender rewrite status
check_enabled_sender_rewrite() {
    if [ -f "$PF_IN" ]                                                              \
        && grep -q "sender_canonical_maps=regexp:$SENDER_REWRITE" "$PF_IN"; then
        echo on
    else
        echo off
    fi
}
# check whether sender dependent routing is enabled
# parameters:
# none
# return values:
# sender dependent routing status
check_enabled_sender_routing() {
    if [ -f "$PF_IN" ]                                                                                              \
        && grep -q "sender_dependent_default_transport_maps=hash:$SENDER_ROUTING" "$PF_IN"; then
        echo on
    else
        echo off
    fi
}
# check whether inbound bounce notification is enabled
# parameters:
# none
# return values:
# inbound bounce notification status
check_enabled_bounce_in() {
    if [ -f "$PF_IN" ]                                                                                      \
        && grep -q 'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce' "$PF_IN"   \
        && grep -q "2bounce_notice_recipient=$EMAIL_BOUNCE" "$PF_IN"                                        \
        && grep -q "bounce_notice_recipient=$EMAIL_BOUNCE" "$PF_IN"                                         \
        && grep -q "delay_notice_recipient=$EMAIL_BOUNCE" "$PF_IN"                                          \
        && grep -q "error_notice_recipient=$EMAIL_BOUNCE" "$PF_IN"; then
        echo on
    else
        echo off
    fi
}
# check whether outbound bounce notification is enabled
# parameters:
# none
# return values:
# outbound bounce notification status
check_enabled_bounce_out() {
    if [ -f "$PF_OUT" ]                                                                                     \
        && grep -q 'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce' "$PF_OUT"  \
        && grep -q "2bounce_notice_recipient=$EMAIL_BOUNCE" "$PF_OUT"                                       \
        && grep -q "bounce_notice_recipient=$EMAIL_BOUNCE" "$PF_OUT"                                        \
        && grep -q "delay_notice_recipient=$EMAIL_BOUNCE" "$PF_OUT"                                         \
        && grep -q "error_notice_recipient=$EMAIL_BOUNCE" "$PF_OUT"; then
        echo on
    else
        echo off
    fi
}
# check whether Office365 IP range whitelisting is enabled
# parameters:
# none
# return values:
# Office365 IP range whitelisting status
check_enabled_office365() {
    if [ -f "$PF_IN" ]                                                                              \
        && grep -q "smtpd_relay_restrictions=check_client_access cidr:$MAP_OFFICE365, " "$PF_IN"; then
        echo on
    else
        echo off
    fi
}
# check whether Postscreen is enabled
# parameters:
# none
# return values:
# Postscreen status
check_enabled_postscreen() {
    if [ -f "$CONFIG_PF" ]                                                                                                                                              \
        && grep -q "postconf -c $PF_INBOUND -M# '25/inet'" "$CONFIG_PF"                                                                                                 \
        && grep -q "postconf -c $PF_INBOUND -Me '25/inet=25  inet n - n - 1 postscreen'" "$CONFIG_PF"                                                                   \
        && grep -q "postconf -c $PF_INBOUND -Me 'smtpd/pass=smtpd      pass  -       -       n       -       -       smtpd'" "$CONFIG_PF"                               \
        && grep -q "postconf -c $PF_INBOUND -Me 'dnsblog/unix=dnsblog    unix  -       -       n       -       0       dnsblog'" "$CONFIG_PF"                           \
        && grep -q "postconf -c $PF_INBOUND -Me 'tlsproxy/unix=tlsproxy   unix  -       -       n       -       0       tlsproxy'" "$CONFIG_PF"                         \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_access_list=permit_mynetworks cidr:$WHITELIST_POSTSCREEN'" "$CONFIG_PF"                                      \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_blacklist_action=enforce'" "$CONFIG_PF"                                                                      \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_command_time_limit=\${stress?10}\${stress:300}s'" "$CONFIG_PF"                                               \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_action=enforce'" "$CONFIG_PF"                                                                          \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_sites=$(echo $BLACKLISTS | sed 's/\[/\\\[/g' | sed 's/\]/\\\]/g' | sed 's/\*/\\\*/g')'" "$CONFIG_PF"   \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_threshold=3'" "$CONFIG_PF"                                                                             \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_ttl=1h'" "$CONFIG_PF"                                                                                  \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_greet_action=enforce'" "$CONFIG_PF"                                                                          \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_greet_wait=\${stress?4}\${stress:15}s'" "$CONFIG_PF"; then
        echo on
    else
        echo off
    fi
}
# check whether Postscreen Deep inspection is enabled
# parameters:
# none
# return values:
# Postscreen Deep inspection status
check_enabled_postscreen_deep() {
    if [ -f $CONFIG_PF ]                                                                                        \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_enable=yes'" "$CONFIG_PF"               \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_action=enforce'" "$CONFIG_PF"           \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_action=enforce'" "$CONFIG_PF"       \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_enable=yes'" "$CONFIG_PF"           \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_pipelining_enable=yes'" "$CONFIG_PF"                 \
        && grep -q "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_whitelist_threshold=-1'" "$CONFIG_PF"; then
        echo on
    else
        echo off
    fi
}
###################################################################################################
# select features to enable in dialog checkbox
# parameters:
# none
# return values:
# none
dialog_feature_postfix() {
    DIALOG_RSPAMD='Rspamd'
    DIALOG_LETSENCRYPT="Let's Encrypt Cert"
    DIALOG_TLS='Verbose TLS'
    DIALOG_ESMTP_FILTER='ESMTP-filter'
    DIALOG_DANE='DANE'
    DIALOG_SENDER_REWRITE='Sender rewrite'
    DIALOG_SENDER_ROUTING='Sender dependent routing'
    DIALOG_BOUNCE_IN='Inbound-Bounce'
    DIALOG_BOUNCE_OUT='Outbound-Bounce'
    DIALOG_OFFICE365='Office365 IP-range whitelisting'
    DIALOG_POSTSCREEN='Postscreen'
    DIALOG_POSTSCREEN_DEEP='PS Deep'
    for FEATURE in rspamd letsencrypt tls esmtp_filter dane sender_rewrite sender_routing bounce_in bounce_out office365 postscreen postscreen_deep; do
        declare STATUS_${FEATURE^^}="$(check_enabled_$FEATURE)"
    done
    [ "$STATUS_BOUNCE_IN" = 'on' ] && EMAIL_BOUNCE_IN="$(grep '^bounce_notice_recipient=' $PF_IN | awk -F\= '{print $2}' | tr -d \')" || EMAIL_BOUNCE_IN=''
    [ "$STATUS_BOUNCE_OUT" = 'on' ] && EMAIL_BOUNCE_OUT="$(grep '^bounce_notice_recipient=' $PF_OUT | awk -F\= '{print $2}' | tr -d \')" || EMAIL_BOUNCE_OUT=''
    ARRAY_ENABLE=()
    check_installed_rspamd && ARRAY_ENABLE+=("$DIALOG_RSPAMD" '' "$STATUS_RSPAMD")
    check_installed_letsencrypt && ARRAY_ENABLE+=("$DIALOG_LETSENCRYPT" '' "$STATUS_LETSENCRYPT")
    ARRAY_ENABLE+=("$DIALOG_TLS" '' "$STATUS_TLS")
    ARRAY_ENABLE+=("$DIALOG_ESMTP_FILTER" '' "$STATUS_ESMTP_FILTER")
    check_installed_local_dns && ARRAY_ENABLE+=("$DIALOG_DANE" '' "$STATUS_DANE")
    ARRAY_ENABLE+=("$DIALOG_SENDER_REWRITE" '' "$STATUS_SENDER_REWRITE")
    ARRAY_ENABLE+=("$DIALOG_SENDER_ROUTING" '' "$STATUS_SENDER_ROUTING")
    ARRAY_ENABLE+=("$DIALOG_BOUNCE_IN" '' "$STATUS_BOUNCE_IN")
    ARRAY_ENABLE+=("$DIALOG_BOUNCE_OUT" '' "$STATUS_BOUNCE_OUT")
    ARRAY_ENABLE+=("$DIALOG_OFFICE365" '' "$STATUS_OFFICE365")
    ARRAY_ENABLE+=("$DIALOG_POSTSCREEN" '' "$STATUS_POSTSCREEN")
    ARRAY_ENABLE+=("$DIALOG_POSTSCREEN_DEEP" '' "$STATUS_POSTSCREEN_DEEP")
    exec 3>&1
    DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Apply' --checklist 'Choose Postfix features to enable' 0 0 0 "${ARRAY_ENABLE[@]}" 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        LIST_ENABLED=''
        POSTFIX_RESTART=''
        if check_installed_rspamd; then
            if echo "$DIALOG_RET" | grep -q "$DIALOG_RSPAMD"; then
                if [ "$STATUS_RSPAMD" = 'off' ]; then
                    enable_rspamd
                    POSTFIX_RESTART=1
                fi
                LIST_ENABLED+=$'\n''Rspamd'
            else
                if [ "$STATUS_RSPAMD" = 'on' ]; then
                    disable_rspamd
                    APPLY_NEEDED=1
                fi
            fi
        fi
        if check_installed_letsencrypt; then
            if echo "$DIALOG_RET" | grep -q "$DIALOG_LETSENCRYPT"; then
                if [ "$STATUS_LETSENCRYPT" = 'off' ]; then
                    enable_letsencrypt
                    POSTFIX_RESTART=1
                fi
                LIST_ENABLED+=$'\n'"Let's Encrypt cert"
            else
                if [ "$STATUS_LETSENCRYPT" = 'on' ]; then
                    disable_letsencrypt
                    APPLY_NEEDED=1
                fi
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_TLS"; then
            if [ "$STATUS_TLS" = 'off' ]; then
                enable_tls
                POSTFIX_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Verbose TLS'
        else
            if [ "$STATUS_TLS" = 'on' ]; then
                disable_tls
                APPLY_NEEDED=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_ESMTP_FILTER"; then
            if [ "$STATUS_ESMTP_FILTER" = 'off' ]; then
                enable_esmtp_filter
                POSTFIX_RESTART=1
            fi
            LIST_ENABLED+=$'\n''ESMTP-filter'
        else
            if [ "$STATUS_ESMTP_FILTER" = 'on' ]; then
                disable_esmtp_filter
                APPLY_NEEDED=1
            fi
        fi
        if check_installed_local_dns; then
            if echo "$DIALOG_RET" | grep -q "$DIALOG_DANE"; then
                if [ "$STATUS_DANE" = 'off' ]; then
                    enable_dane
                    POSTFIX_RESTART=1
                fi
                LIST_ENABLED+=$'\n''DANE'
            else
                if [ "$STATUS_DANE" = 'on' ]; then
                    disable_dane
                    APPLY_NEEDED=1
                fi
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_SENDER_REWRITE"; then
            if [ "$STATUS_SENDER_REWRITE" = 'off' ]; then
                enable_sender_rewrite
                POSTFIX_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Sender rewrite'
        else
            if [ "$STATUS_SENDER_REWRITE" = 'on' ]; then
                disable_sender_rewrite
                APPLY_NEEDED=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_SENDER_ROUTING"; then
            if [ "$STATUS_SENDER_ROUTING" = 'off' ]; then
                enable_sender_routing
                POSTFIX_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Sender dependent routing'
        else
            if [ "$STATUS_SENDER_ROUTING" = 'on' ]; then
                disable_sender_routing
                APPLY_NEEDED=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_BOUNCE_IN"; then
            if [ "$STATUS_BOUNCE_IN" = 'off' ]; then
                enable_bounce_in "$EMAIL_BOUNCE_IN" && LIST_ENABLED="$LIST_ENABLED"$'\n''Inbound-Bounce' && POSTFIX_RESTART=1
            fi
        else
            if [ "$STATUS_BOUNCE_IN" = 'on' ]; then
                disable_bounce_in "$EMAIL_BOUNCE_IN"
                APPLY_NEEDED=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_BOUNCE_OUT"; then
            if [ "$STATUS_BOUNCE_OUT" = 'off' ]; then
                enable_bounce_out "$EMAIL_BOUNCE_OUT" && LIST_ENABLED="$LIST_ENABLED"$'\n''Outbound-Bounce' && POSTFIX_RESTART=1
            fi
        else
            if [ "$STATUS_BOUNCE_OUT" = 'on' ]; then
                disable_bounce_out "$EMAIL_BOUNCE_OUT"
                APPLY_NEEDED=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_OFFICE365"; then
            if [ "$STATUS_OFFICE365" = 'off' ]; then
                enable_office365
                POSTFIX_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Office365 IP-range whitelisting'
        else
            if [ "$STATUS_OFFICE365" = 'on' ]; then
                disable_office365
                APPLY_NEEDED=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_POSTSCREEN"; then
            if [ "$STATUS_POSTSCREEN" = 'off' ]; then
                enable_postscreen
                APPLY_NEEDED=1
            fi
            LIST_ENABLED+=$'\n''Postscreen'
        else
            if [ "$STATUS_POSTSCREEN" = 'on' ]; then
                disable_postscreen
                APPLY_NEEDED=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_POSTSCREEN_DEEP"; then
            if [ "$STATUS_POSTSCREEN_DEEP" = 'off' ]; then
                enable_postscreen_deep
                APPLY_NEEDED=1
            fi
            LIST_ENABLED+=$'\n''Postscreen-Deep'
        else
            if [ "$STATUS_POSTSCREEN_DEEP" = 'on' ]; then
                disable_postscreen_deep
                APPLY_NEEDED=1
            fi
        fi
        [ -z "$LIST_ENABLED" ] && LIST_ENABLED="$LIST_ENABLED"$'\n'"None"
        chown -R cs-admin:cs-adm /opt/cs-gateway/custom
        if [ "$APPLY_NEEDED" = 1 ]; then
            LIST_ENABLED="$LIST_ENABLED"$'\n\n'"IMPORTANT: Apply configuration in main menu to activate."
        else
            if [ "$POSTFIX_RESTART" = 1 ]; then
                postfix stop &>/dev/null
                postfix start &>/dev/null
            fi
            LIST_ENABLED="$LIST_ENABLED"$'\n\n'
        fi
        $DIALOG --backtitle "$TITLE_MAIN" --title 'Enabled features' --clear --msgbox "$LIST_ENABLED" 0 0
    fi
}
###################################################################################################
# some custom settings
###################################################################################################
install_command() {
    LIST_COMMAND="$(wget https://github.com/netcon-consulting/cs-menu/tree/master/external_commands -O - 2>/dev/null | sed -n '/<tr class="js-navigation-item">/,/<\/tr>/p' | awk 'match($0, / title="([^"]+)" /, a) {print a[1]}')"
    while true; do
        ARRAY_COMMAND=()
        for NAME_COMMAND in $LIST_COMMAND; do
            ARRAY_COMMAND+=("$NAME_COMMAND" '')
        done
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle 'Manage configuration' --title 'External commands' --cancel-label 'Back' --ok-label 'Install' --extra-button --extra-label 'Info'        \
            --menu 'Install external command' 0 0 0 "${ARRAY_COMMAND[@]}" 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            wget "$LINK_GITHUB/external_commands/$DIALOG_RET/$DIALOG_RET.sh" -O "$DIR_COMMANDS/$DIALOG_RET.sh" 2>/dev/null
            chown cs-admin:cs-adm "$DIR_COMMANDS/$DIALOG_RET.sh"
            chmod +x "$DIR_COMMANDS/$DIALOG_RET.sh"
            RESULT="$(create_rule "$(wget "$LINK_GITHUB/external_commands/$DIALOG_RET/$DIALOG_RET.rule" -O - 2>/dev/null)")"
            if [ "$?" = 0 ]; then
                APPLY_NEEDED=1
            else
                $DIALOG --backtitle 'Manage configuration' --title 'Error importing policy rule' --clear --msgbox "Error: $RESULT" 0 0
            fi
        elif [ $RET_CODE = 3 ]; then
            INFO_COMMAND="$(wget "$LINK_GITHUB/external_commands/$DIALOG_RET/README.md" -O - 2>/dev/null)"
            [ -z "$INFO_COMMAND" ] || $DIALOG --backtitle 'Manage configuration' --title 'External command info' --clear --msgbox "$INFO_COMMAND" 0 0
        else
            break
        fi
    done
}
# edit LDAP schedule
# parameters:
# none
# return values:
# none
ldap_schedule() {
    TMP_LDAP='/tmp/TMPldap'
    TMP_LDAP_OLD='/tmp/TMPldap_old'
    if [ -f $CONFIG_LDAP ]; then
        cp -f $CONFIG_LDAP $TMP_LDAP
    else
        cp -f /opt/cs-gateway/ldapagent/schedule.properties $TMP_LDAP
        sed -i 's/absolute=true/absolute=false/' $TMP_LDAP
    fi
    cp -f $TMP_LDAP $TMP_LDAP_OLD
    $TXT_EDITOR $TMP_LDAP
    [ -z "$(diff -q $TMP_LDAP $TMP_LDAP_OLD)" ] || cp -f $TMP_LDAP $CONFIG_LDAP
}
# add IP range for SSH access in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_ssh() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Manage SSH access' --title 'Add allowed IP/-range' --inputbox 'Enter allowed IP/-range for SSH access' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        echo "-I INPUT 4 -i eth0 -p tcp --dport 22 -s $DIALOG_RET -j ACCEPT" >> $CONFIG_FW
        iptables -I INPUT 4 -i eth0 -p tcp --dport 22 -s $DIALOG_RET -j ACCEPT
        return 0
    else
        return 1
    fi
}
# add/remove IP ranges for SSH access in dialog menu
# parameters:
# none
# return values:
# none
ssh_access() {
    while true; do
        LIST_IP=''
        [ -f $CONFIG_FW ] && LIST_IP=$(grep 'I INPUT 4 -i eth0 -p tcp --dport 22 -s ' $CONFIG_FW | awk '{print $11}')
        if [ -z "$LIST_IP" ]; then
            add_ssh || break
        else
            ARRAY_IP=()
            for IP_ADDRESS in $LIST_IP; do
                ARRAY_IP+=($IP_ADDRESS '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Manage configuration' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove IPs for SSH access' 0 0 0 "${ARRAY_IP[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_ssh
            else
                if [ $RET_CODE = 3 ]; then
                    IP_ADDRESS="$(echo "$DIALOG_RET" | sed 's/\//\\\//g')"
                    sed -i "/-I INPUT 4 -i eth0 -p tcp --dport 22 -s $IP_ADDRESS -j ACCEPT/d" $CONFIG_FW
                    iptables -D INPUT -i eth0 -p tcp --dport 22 -s $DIALOG_RET -j ACCEPT
                else
                    break
                fi
            fi
        fi
    done
}
# add IP range for blocking SMTP access in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_block() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Manage SMTP access' --title 'Add blocked IP/-range' --inputbox 'Enter IP/-range for blocking SMTP access' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        echo "-I INPUT 4 -i eth0 -p tcp --dport 25 -s $DIALOG_RET -j REJECT" >> $CONFIG_FW
        iptables -I INPUT 4 -i eth0 -p tcp --dport 25 -s $DIALOG_RET -j REJECT
        return 0
    else
        return 1
    fi
}
# add/remove IP ranges for blocking SMTP access in dialog menu
# parameters:
# none
# return values:
# none
smtp_block() {
    while true; do
        LIST_IP=''
        [ -f $CONFIG_FW ] && LIST_IP=$(grep 'I INPUT 4 -i eth0 -p tcp --dport 25 -s ' $CONFIG_FW | awk '{print $11}')
        if [ -z "$LIST_IP" ]; then
            add_block || break
        else
            ARRAY_IP=()
            for IP_ADDRESS in $LIST_IP; do
                ARRAY_IP+=($IP_ADDRESS '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Manage configuration' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove IPs for blocking SMTP access' 0 0 0 "${ARRAY_IP[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_block
            else
                if [ $RET_CODE = 3 ]; then
                    IP_ADDRESS="$(echo "$DIALOG_RET" | sed 's/\//\\\//g')"
                    sed -i "/-I INPUT 4 -i eth0 -p tcp --dport 25 -s $IP_ADDRESS -j REJECT/d" $CONFIG_FW
                    iptables -D INPUT -i eth0 -p tcp --dport 25 -s $DIALOG_RET -j REJECT
                else
                    break
                fi
            fi
        fi
    done
}
# add public key for SSH authentication for cs-admin in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_key() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Manage SSH key authentication' --title 'Add public SSH key' --inputbox 'Enter public key for SSH authentication for cs-admin' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        if ! grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config                    ||
            ! grep -q "^AuthorizedKeysFile .ssh/authorized_keys" /etc/ssh/sshd_config ]  ||
            ! [ -d /home/cs-admin/.ssh ]; then
            echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
            echo "AuthorizedKeysFile .ssh/authorized_keys" >> /etc/ssh/sshd_config
            mkdir /home/cs-admin/.ssh
            chmod 700 /home/cs-admin/.ssh
            chown cs-admin:cs-adm /home/cs-admin/.ssh
            restorecon -R -v /home/cs-admin/.ssh
            service sshd restart
        fi
        echo "$DIALOG_RET" >> $SSH_KEYS
        return 0
    else
        return 1
    fi
}
# add/remove public keys for SSH authentication for cs-admin in dialog menu
# parameters:
# none
# return values:
# none
key_auth() {
    while true; do
        LIST_KEY=""
        [ -f $SSH_KEYS ] && LIST_KEY=$(sed 's/ /,/g' $SSH_KEYS)
        if [ -z "$LIST_KEY" ]; then
            add_key || break
        else
            ARRAY_KEY=()
            for SSH_KEY in $LIST_KEY; do
                ARRAY_KEY+=("$(echo $SSH_KEY | sed 's/,/ /g')" '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Manage configuration' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove public keys for SSH authentication for cs-admin' 0 0 0 "${ARRAY_KEY[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_key
            else
                if [ $RET_CODE = 3 ]; then
                    sed -i "/$(echo "$DIALOG_RET" | sed 's/\//\\\//g')/d" $SSH_KEYS
                else
                    break
                fi
            fi
        fi
    done
}
# import PKCS12 keystore to CS Tomcat
# parameters:
# none
# return values:
# none
import_keystore() {
    TMP_KEYSTORE='/tmp/TMPkeystore'
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Manage configuration' --title 'Import PKCS12 keystore'                              \
        --inputbox "Enter filename of keystore to import [Note: keystore password must be '$PASSWORD_KEYSTORE']" 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ "$RET_CODE" = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        if [ -f "$DIALOG_RET" ]; then
            keytool -importkeystore -destkeystore "$TMP_KEYSTORE" -srckeystore "$DIALOG_RET" -srcstoretype pkcs12 -deststorepass "$PASSWORD_KEYSTORE" -srcstorepass "$PASSWORD_KEYSTORE" &>/dev/null
            if [ "$?" = 0 ]; then
                mv /var/cs-gateway/keystore /var/cs-gateway/keystore.old
                mv "$TMP_KEYSTORE" /var/cs-gateway/keystore
                cs-servicecontrol restart tomcat &>/dev/null
            else
                $DIALOG --backtitle 'Manage configuration' --title 'Error importing keystore' --clear --msgbox 'Error importing keystore' 0 0
            fi
        else
            $DIALOG --backtitle 'Manage configuration' --title 'File does not exist' --clear --msgbox "File '$DIALOG_RET' does not exist" 0 0
        fi
    fi
}
# get address table from CS config
# parameters:
# none
# return values:
# none
get_addr_table() {
    [ -f "$LAST_CONFIG" ] && cat "$LAST_CONFIG" | grep -o -P '(?<=\<AddressListTable\>).*(?=\<\/AddressListTable\>)'
}
# get address lists from address table
# parameters:
# none
# return values:
# none
get_addr_list() {
    get_addr_table | awk -F 'AddressList' '{for (i=1; i<=(NF+1)/2; ++i) print $(i*2)}'
}
# get addresses from address list
# parameters:
# none
# return values:
# none
get_addr() {
    ADDR="$(echo "$1" | awk -F 'Address' '{for (i=1; i<=(NF+1)/2; ++i) print $(i*2)}'| cut -d \> -f 2 | cut -d \< -f 1)"
    [ -z "$ADDR" ] || echo "$ADDR"
}
# export and email address lists from CS config
# parameters:
# none
# return values:
# none
export_address_list() {
    rm -rf "$DIR_ADDRLIST"
    mkdir -p "$DIR_ADDRLIST"
    LIST_EXPORTED='Address lists exported:'$'\n'
    while read LINE; do
        if [ ! -z "$LINE" ]; then
            NAME_LIST=$(echo "$LINE" | awk 'match($0, /name="([^"]+)"/, a) {print a[1]}' | sed 's/ /_/g')
            get_addr "$LINE" > "$DIR_ADDRLIST/$NAME_LIST".lst
            LIST_EXPORTED+=$'\n'"$NAME_LIST.lst"
        fi
    done < <(get_addr_list)
    FILE_ADDRLIST="/tmp/address_lists_$(date +%F).tgz"
    tar -C "$DIR_ADDRLIST" -czf "$FILE_ADDRLIST" .
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Clearswift Configuration' --title 'Export and email address lists'  \
        --inputbox 'Enter email recipient for address lists' 0 50 $EMAIL_DEFAULT 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        DOMAIN_RECIPIENT="$(echo "$DIALOG_RET"| awk -F"@" '{print $2}')"
        MAIL_RELAY=''
        [ -f "$MAP_TRANSPORT" ] && MAIL_RELAY="$(grep "^$DOMAIN_RECIPIENT " $MAP_TRANSPORT | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
        [ -z "$MAIL_RELAY" ] && MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
        if [ -z "$MAIL_RELAY" ]; then
            $DIALOG --backtitle 'Clearswift Configuration' --title 'Export address lists' --clear --msgbox 'Cannot determine mail relay' 0 0
        else
            echo '[CS-addresslists] Exported addresslists' | mail -s '[CS-addresslists] Exported addresslists' -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) -a "$FILE_ADDRLIST" "$DIALOG_RET"
            LIST_EXPORTED+=$'\n\n'"Archive of exported addresslist send to '$DIALOG_RET' and local copy saved to '$FILE_ADDRLIST'."
            $DIALOG --backtitle 'Clearswift Configuration' --title 'Export address lists' --clear --msgbox "$LIST_EXPORTED" 0 0
        fi
    fi
}
# create 'run external command' policy rule from config file
# parameters:
# $1 - rule config
# return values:
# none
create_rule() {
    DIR_CFG='/var/cs-gateway/uicfg'
    DIR_RULES="$DIR_CFG/policy/rules"
    DIR_URL="$DIR_CFG/policy/urllists"
    FILE_DISPOSAL="$DIR_CFG/policy/disposals.xml"

    if [ -z "$1" ]; then
        echo "rule config is empty"
        return 1
    fi

    NAME_RULE="$(echo "$1" | sed -n '/name_rule/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if [ -z "$NAME_RULE" ]; then
        echo "'name_rule' is empty"
        return 2
    fi

    PATH_CMD="$(echo "$1" | sed -n '/path_cmd/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if [ -z "$PATH_CMD" ]; then
        echo "'path_cmd' is empty"
        return 3
    fi

    TIMEOUT="$(echo "$1" | sed -n '/timeout/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if [ -z "$TIMEOUT" ]; then
        echo "'timeout' is empty"
        return 4
    fi

    LIST_MEDIA="$(echo "$1" | sed -n '/media_types/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if [ -z "$LIST_MEDIA" ]; then
        echo "'media_types' is empty"
        return 5
    fi

    LIST_CODE="$(echo "$1" | sed -n '/return_codes/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if [ -z "$LIST_CODE" ]; then
        echo "'return_codes' is empty"
        return 6
    fi

    LIST_DISPOSAL="$(echo "$1" | sed -n '/disposal_actions/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if [ -z "$LIST_DISPOSAL" ]; then
        echo "'disposal_actions' is empty"
        return 7
    fi

    LIST_DEPENDENCY="$(echo "$1" | sed -n '/dependencies/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if ! [ -z "$LIST_DEPENDENCY" ]; then
        install_epel &>/dev/null
        for DEPENDENCY in $LIST_DEPENDENCY; do
            yum install -y "$DEPENDENCY" --enablerepo=cs-* &>/dev/null
            if [ "$?" != 0 ]; then
                echo "cannot install '$DEPENDENCY'"
                return 8
            fi
        done
    fi

    if ! [ -z "$(xmlstarlet sel -t -m "Configuration/PolicyRuleCollection/ExecutablePolicyRule[@name='$NAME_RULE']" -v @uuid -n "$LAST_CONFIG")" ] || ! [ -z "$(xmlstarlet sel -t -m "ExecutablePolicyRule[@name='$NAME_RULE']" -v @uuid -n $DIR_RULES/*.xml)" ]; then
        echo "rule '$NAME_RULE' already exists"
        return 9
    fi

    LIST_URL="$(echo "$1" | sed -n '/url_lists/,/^\s*$/p' | sed '/^\s*$/d' | sed -n '1!p')"

    if ! [ -z "$LIST_URL" ]; then
        while read NAME_LIST; do
            if ! grep -q "UrlList name=\"$NAME_LIST\"" "$DIR_URL/*.xml" 2>/dev/null; then
                UUID_WHITELIST="$(uuidgen)"
                FILE_WHITELIST="$DIR_URL/$UUID_WHITELIST.xml"
                echo "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><UrlList name=\"$NAME_LIST\" type=\"CUSTOM\" uuid=\"$UUID_WHITELIST\"><Url>isdoll.de</Url></UrlList>" > "$FILE_WHITELIST"
                chown cs-tomcat:cs-adm "$FILE_WHITELIST"
                chmod g+w "$FILE_WHITELIST"
            fi
        done < <(echo "$LIST_URL")
    fi

    LIST_TYPE="$(xmlstarlet sel -t -m "Configuration/MediaTypes/MediaTypeGroup/MediaType[@name!='New']" -v @mnemonic -o "," -v @uuid -o "," -v @encrypted -o "," -v @signed -o "," -v @signedAndEncrypted -o "," -v @drm -o "," -v @notProtected -n $LAST_CONFIG)"

    LIST_AREA="$(xmlstarlet sel -t -m "Configuration/DisposalCollection/MessageArea" -v @name -o "," -v @uuid -n $LAST_CONFIG)"

    ACTION_DROP="$(xmlstarlet sel -t -m "Configuration/DisposalCollection/Drop" -v @uuid -n $LAST_CONFIG)"
    ACTION_NDR="$(xmlstarlet sel -t -m "Configuration/DisposalCollection/NDR" -v @uuid -n $LAST_CONFIG)"
    ACTION_DELIVER="$(xmlstarlet sel -t -m "Configuration/DisposalCollection/Deliver" -v @uuid -n $LAST_CONFIG)"
    ACTION_NONE="$(xmlstarlet sel -t -m "Configuration/DisposalCollection/None" -v @uuid -n $LAST_CONFIG)"
    ACTION_REJECT="$(xmlstarlet sel -t -m "Configuration/DisposalCollection/Reject" -v @uuid -n $LAST_CONFIG)"
    ACTION_TAG="$(xmlstarlet sel -t -m "Configuration/DisposalCollection/TagAndDeliver" -v @uuid -n $LAST_CONFIG)"

    for DISPOSAL in $(echo "$LIST_DISPOSAL" | awk -F, '{print $2}'); do
        if ! echo "$DISPOSAL" | grep -E -q '^(drop|ndr|deliver|none|reject|tag)$' && ! grep -q " name=\"$DISPOSAL\" notificationEnabled=" "$FILE_DISPOSAL"; then
            UUID_DISPOSAL="$(uuidgen)"
            sed -i "s/<\/DisposalCollection>/<MessageArea auditorNotificationAuditor=\"admin\" auditorNotificationAuditorAddress=\"\" auditorNotificationEnabled=\"false\" auditorNotificationpwdOtherAddress=\"\" auditorNotificationPlainBody=\"A message was released by %RELEASEDBY% which violated the policy %POLICYVIOLATED%. A version of the email has been attached.\&#10;\&#10;To: %RCPTS%\&#10;Subject: %SUBJECT%\&#10;Date sent: %DATE%\" auditorNotificationSender=\"admin\" auditorNotificationSubject=\"A message which violated policy %POLICYVIOLATED% has been released.\" delayedReleaseDelay=\"15\" expiry=\"30\" name=\"$DISPOSAL\" notificationEnabled=\"false\" notificationOtherAddress=\"\" notificationPlainBody=\"A message you sent has been released by the administrator\&#10;\&#10;To: %RCPTS%\&#10;Subject: %SUBJECT%\&#10;Date sent: %DATE%\" notificationSender=\"admin\" notificationSubject=\"A message you sent has been released\" notspam=\"true\" pmm=\"false\" releaseRate=\"10000\" releaseScheduleType=\"throttle\" scheduleEnabled=\"false\" system=\"false\" uuid=\"$UUID_DISPOSAL\"><PMMAddressList\/><WeeklySchedule mode=\"ONE_HOUR\"><DailyScheduleList><DailySchedule day=\"1\" mode=\"ONE_HOUR\">000000000000000000000000<\/DailySchedule><DailySchedule day=\"2\" mode=\"ONE_HOUR\">000000000000000000000000<\/DailySchedule><DailySchedule day=\"3\" mode=\"ONE_HOUR\">000000000000000000000000<\/DailySchedule><DailySchedule day=\"4\" mode=\"ONE_HOUR\">000000000000000000000000<\/DailySchedule><DailySchedule day=\"5\" mode=\"ONE_HOUR\">000000000000000000000000<\/DailySchedule><DailySchedule day=\"6\" mode=\"ONE_HOUR\">000000000000000000000000<\/DailySchedule><DailySchedule day=\"7\" mode=\"ONE_HOUR\">000000000000000000000000<\/DailySchedule><\/DailyScheduleList><\/WeeklySchedule><\/MessageArea><\/DisposalCollection>/" "$FILE_DISPOSAL"
            LIST_AREA+=$'\n'"$DISPOSAL,$UUID_DISPOSAL"
        fi
    done

    UUID_RULE="$(uuidgen)"

    POLICY_RULE="<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><ExecutablePolicyRule name=\"$NAME_RULE\" siteSpecific=\"false\" template=\"9255cf2d-3000-832b-406e-38bd46975444\" uuid=\"$UUID_RULE\"><WhatToFind><MediaTypes selection=\"anyof\" uuid=\"$(uuidgen)\">"

    while read LINE_MEDIA; do
        MEDIA_TYPE=''

        NAME_MEDIA="$(echo $LINE_MEDIA | awk -F, '{print $1}')"

        while read LINE_TYPE; do
            NAME_TYPE="$(echo $LINE_TYPE | awk -F, '{print $1}')"

            if [ "$NAME_MEDIA" = "$NAME_TYPE" ]; then
                MEDIA_TYPE+='<MediaType'

                INDEX=1

                if ! [ -z "$(echo $LINE_TYPE | awk -F, '{print $3}')" ]; then
                    INDEX="$(expr $INDEX + 1)"
                    MEDIA_TYPE+=" enc=\"$(echo $LINE_MEDIA | awk -F, "{print $"$INDEX"}")\""
                fi
                if ! [ -z "$(echo $LINE_TYPE | awk -F, '{print $4}')" ]; then
                    INDEX="$(expr $INDEX + 1)"
                    MEDIA_TYPE+=" digsign=\"$(echo $LINE_MEDIA | awk -F, "{print $"$INDEX"}")\""
                fi
                if ! [ -z "$(echo $LINE_TYPE | awk -F, '{print $5}')" ]; then
                    INDEX="$(expr $INDEX + 1)"
                    MEDIA_TYPE+=" digsignenc=\"$(echo $LINE_MEDIA | awk -F, "{print $"$INDEX"}")\""
                fi
                if ! [ -z "$(echo $LINE_TYPE | awk -F, '{print $6}')" ]; then
                    INDEX="$(expr $INDEX + 1)"
                    MEDIA_TYPE+=" drm=\"$(echo $LINE_MEDIA | awk -F, "{print $"$INDEX"}")\""
                fi
                if ! [ -z "$(echo $LINE_TYPE | awk -F, '{print $7}')" ]; then
                    INDEX="$(expr $INDEX + 1)"
                    MEDIA_TYPE+=" notprotect=\"$(echo $LINE_MEDIA | awk -F, "{print $"$INDEX"}")\""
                fi

                MEDIA_TYPE+=">$(echo $LINE_TYPE | awk -F, '{print $2}')</MediaType>"

                break
            fi
        done < <(echo "$LIST_TYPE")

        POLICY_RULE+="$MEDIA_TYPE"
    done < <(echo "$LIST_MEDIA")

    POLICY_RULE+="</MediaTypes><Direction direction=\"either\" uuid=\"$(uuidgen)\"/><ExecutableSettings uuid=\"$(uuidgen)\"><Filename>$PATH_CMD</Filename><CmdLine>%FILENAME% %LOGNAME%</CmdLine><ResponseList>"

    while read LINE_CODE; do
        POLICY_RULE+="<Response action=\"$(echo $LINE_CODE | awk -F, '{print $2}' | tr [a-z] [A-Z])\" code=\"$(echo $LINE_CODE | awk -F, '{print $1}')\">$(echo $LINE_CODE | awk -F, '{print $3}')</Response>"
    done < <(echo "$LIST_CODE")

    POLICY_RULE+="</ResponseList><Advanced mutex=\"false\" timeout=\"$TIMEOUT\"><LogFilePrefix>&gt;&gt;&gt;&gt;</LogFilePrefix><LogFilePostfix>&lt;&lt;&lt;&lt;</LogFilePostfix></Advanced></ExecutableSettings></WhatToFind><PrimaryActions><WhatToDo><Disposal disposal=\"$ACTION_DELIVER\" primaryCrypto=\"UNDEFINED\" secondary=\"$ACTION_NONE\" secondaryCrypto=\"UNDEFINED\" uuid=\"$(uuidgen)\"/></WhatToDo><WhatToDoWeb><PrimaryWebAction editable=\"true\" type=\"allow\" uuid=\"$(uuidgen)\"/></WhatToDoWeb><WhatElseToDo/></PrimaryActions>"

    DISPOSAL="$(echo "$LIST_DISPOSAL" | grep '^modified,' | awk -F, '{print $2}')"
    case "$DISPOSAL" in
        drop|ndr|deliver|none|reject|tag)
            ACTION_PRIMARY="$(eval echo '$'ACTION_${DISPOSAL^^})";;
        *)
            ACTION_PRIMARY="$(echo "$LIST_AREA" | grep "^$DISPOSAL," | awk -F, '{print $2}')";;
    esac
    DISPOSAL="$(echo "$LIST_DISPOSAL" | grep '^modified,' | awk -F, '{print $3}')"
    case "$DISPOSAL" in
        drop|ndr|deliver|none|reject|tag)
            ACTION_SECONDARY="$(eval echo '$'ACTION_${DISPOSAL^^})";;
        *)
            ACTION_SECONDARY="$(echo "$LIST_AREA" | grep "^$DISPOSAL," | awk -F, '{print $2}')";;
    esac
    POLICY_RULE+="<ModifiedActions><WhatToDo><Disposal disposal=\"$ACTION_PRIMARY\" primaryCrypto=\"UNDEFINED\" secondary=\"$ACTION_SECONDARY\" secondaryCrypto=\"UNDEFINED\" uuid=\"$(uuidgen)\"/></WhatToDo><WhatToDoWeb><PrimaryWebAction editable=\"true\" type=\"none\" uuid=\"$(uuidgen)\"/></WhatToDoWeb><WhatElseToDo/></ModifiedActions>"

    DISPOSAL="$(echo "$LIST_DISPOSAL" | grep '^detected,' | awk -F, '{print $2}')"
    case "$DISPOSAL" in
        drop|ndr|deliver|none|reject|tag)
            ACTION_PRIMARY="$(eval echo '$'ACTION_${DISPOSAL^^})";;
        *)
            ACTION_PRIMARY="$(echo "$LIST_AREA" | grep "^$DISPOSAL," | awk -F, '{print $2}')";;
    esac
    DISPOSAL="$(echo "$LIST_DISPOSAL" | grep '^detected,' | awk -F, '{print $3}')"
    case "$DISPOSAL" in
        drop|ndr|deliver|none|reject|tag)
            ACTION_SECONDARY="$(eval echo '$'ACTION_${DISPOSAL^^})";;
        *)
            ACTION_SECONDARY="$(echo "$LIST_AREA" | grep "^$DISPOSAL," | awk -F, '{print $2}')";;
    esac
    POLICY_RULE+="<DetectedActions><WhatToDo><Disposal disposal=\"$ACTION_PRIMARY\" primaryCrypto=\"UNDEFINED\" secondary=\"$ACTION_SECONDARY\" secondaryCrypto=\"UNDEFINED\" uuid=\"$(uuidgen)\"/></WhatToDo><WhatToDoWeb><PrimaryWebAction editable=\"true\" type=\"none\" uuid=\"$(uuidgen)\"/></WhatToDoWeb><WhatElseToDo/></DetectedActions></ExecutablePolicyRule>"

    echo "$POLICY_RULE" > "$DIR_RULES/$UUID_RULE.xml"
    sed -i 's/changesMade="false"/changesMade="true"/' "$DIR_CFG/trail.xml"

    cs-servicecontrol restart tomcat &>/dev/null

    if [ "$?" != 0 ]; then
        echo 'error restarting Tomcat'
        return 10
    fi
}
# create policy rule from rule config file
# parameters:
# none
# return values:
# none
import_rule() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Manage configuration' --title 'Import policy rule' --inputbox 'Enter filename of rule config file' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ "$RET_CODE" = 0 ] && ! [ -z "$DIALOG_RET" ]; then
        if [ -f "$DIALOG_RET" ]; then
            RESULT="$(create_rule "$(cat "$DIALOG_RET")")"
            [ "$?" = 0 ] || $DIALOG --backtitle 'Manage configuration' --title 'Error importing policy rule' --clear --msgbox "Error: $RESULT" 0 0
        else
            $DIALOG --backtitle 'Manage configuration' --title 'File does not exist' --clear --msgbox "File '$DIALOG_RET' does not exist" 0 0
        fi
    fi
}
# email CS sample policy
# parameters:
# none
# return values:
# none
email_sample() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Clearswift Configuration' --title 'Email sample config' --inputbox 'Enter email for sample config' 0 50 $EMAIL_DEFAULT 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        TMP_CONFIG='/tmp/sample_config.bk'
        wget "$LINK_CONFIG" -O "$TMP_CONFIG" 2>/dev/null
        DOMAIN_RECIPIENT="$(echo "$DIALOG_RET"| awk -F"@" '{print $2}')"
        MAIL_RELAY=''
        [ -f "$TRANSPORT_MAP" ] && MAIL_RELAY="$(grep "^$DOMAIN_RECIPIENT " $TRANSPORT_MAP | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
        [ -z "$MAIL_RELAY" ] && MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
        if [ -z "$MAIL_RELAY" ]; then
            $DIALOG --backtitle 'Manage configuration' --title 'Error sending sample config' --clear --msgbox 'Cannot determine recipient mail relay' 0 0
        else
            echo '[CS-config] Sample CS config' | mail -s '[CS-config] Sample CS config' -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) -a "$TMP_CONFIG" "$DIALOG_RET"
        fi
    fi
}
# create base policy config
# parameters:
# none
# return values:
# none
create_config() {
    DEPLOYMENT_HISTORY='/var/cs-gateway/deployments/deploymenthistory.xml'
    TEMPLATE_CONFIG='/tmp/TMPtemplate_config.xml'

    wget "$LINK_TEMPLATE" -O "$TEMPLATE_CONFIG" 2>/dev/null

    if ! [ -f "$TEMPLATE_CONFIG" ]; then
        echo 'Cannot open config template'
        return 1
    fi

    LIST_ADDRESS="$(xmlstarlet sel -t -m "Configuration/AddressListTable/AddressList[@name='My Company']/Address" -v . -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$LIST_ADDRESS" ]; then
        echo 'Address list is empty'
        return 2
    fi

    INFO_VPN="$(xmlstarlet sel -t -m "Configuration/WebSettings/VPNSettings" -v @allow_grace_period_renewal -o ',' -v @block_internet_access -o ',' -v @external_address -o ',' -v @feature_enabled -o ',' -v @grace_period -o ',' -v @max_grace_period_renewal_times -o ',' -v @network_adapter_uuid -o ',' -v @psk -o ',' -v @remote_connector_port -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$INFO_VPN" ]; then
        echo 'VPN info is empty'
        return 3
    fi

    LIST_NAME="$(xmlstarlet sel -t -m "Configuration/TLSEndPointCollection/TLSEndPoint" -v @name -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$LIST_NAME" ]; then
        echo 'Name list is empty'
        return 4
    fi

    LIST_ENDPOINT=''
    while read NAME; do
        LIST_ENDPOINT+="$(xmlstarlet sel -t -m "Configuration/TLSEndPointCollection/TLSEndPoint[@name = '$NAME']" -v @name -o ',' -v @relayControl -o ',' -v @uuid -n "$LAST_CONFIG" 2>/dev/null),$(xmlstarlet sel -t -m "Configuration/TLSEndPointCollection/TLSEndPoint[@name = '$NAME']/Outbound" -v @certificateValidation -o ',' -v @certificateValidationUserString -o ',' -v @cipherStrength -o ',' -v @enableMandatoryTls -o ',' -v @useGlobalCipherStrength -o ',' -v @useGlobalTlsVersion -o ',' -v @useTls10 -o ',' -v @useTls11 -o ',' -v @useTls12 -n "$LAST_CONFIG" 2>/dev/null),$(xmlstarlet sel -t -m "Configuration/TLSEndPointCollection/TLSEndPoint[@name = '$NAME']/Inbound" -v @certificateCnMatch -o ',' -v @certificateIssuerCnMatch -o ',' -v @checkCertCn -o ',' -v @checkCertIssuerCn -o ',' -v @enableMandatoryTls -o ',' -v @encryptionStrengthBits -o ',' -v @requireValidCertificate -n "$LAST_CONFIG" 2>/dev/null),$(xmlstarlet sel -t -m "Configuration/TLSEndPointCollection/TLSEndPoint[@name = '$NAME']/HostList/Host" -v . -n "$LAST_CONFIG" 2>/dev/null | xargs)"$'\n'
    done < <(echo "$LIST_NAME")
    LIST_ENDPOINT="$(echo "$LIST_ENDPOINT" | sed '/^$/d')"

    if [ -z "$LIST_ENDPOINT" ]; then
        echo 'Endpoint list is empty'
        return 5
    fi

    ADMIN="$(xmlstarlet sel -t -m "Configuration/SmtpSettings/Administrator" -v . -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$ADMIN" ]; then
        echo 'Admin is empty'
        return 6
    fi

    WELCOME="$(xmlstarlet sel -t -m "Configuration/SmtpSettings/Welcome" -v . -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$WELCOME" ]; then
        echo 'Welcome is empty'
        return 7
    fi

    LIST_DOMAIN="$(xmlstarlet sel -t -m "Configuration/SmtpSettings/ManagedDomains/Domain" -v . -o ',' -v @uuid -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$LIST_DOMAIN" ]; then
        echo 'Domain list is empty'
        return 8
    fi

    COUNT_ROUTE="$(xmlstarlet sel -t -m "Configuration/SmtpSettings/RoutingTable" -v @count -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$COUNT_ROUTE" ]; then
        echo 'Route count is empty'
        return 9
    fi

    LIST_ROUTE=''
    for DOMAIN in $(xmlstarlet sel -t -m "Configuration/SmtpSettings/RoutingTable/Route[@domain != '*']" -v @domain -n "$LAST_CONFIG" 2>/dev/null); do
        LIST_ROUTE+="$(xmlstarlet sel -t -m "Configuration/SmtpSettings/RoutingTable/Route[@domain = '$DOMAIN']" -v @domain -o ',' -v @routingType -o ',' -v @tlsEndpointUuid -n "$LAST_CONFIG" 2>/dev/null),$(xmlstarlet sel -t -m "Configuration/SmtpSettings/RoutingTable/Route[@domain = '$DOMAIN']/Server" -v @address -n "$LAST_CONFIG" 2>/dev/null)"$'\n'
    done
    LIST_ROUTE="$(echo "$LIST_ROUTE" | sed '/^$/d')"

    if [ -z "$LIST_ROUTE" ]; then
        echo 'Route list is empty'
        return 10
    fi

    INFO_NETWORK="$(xmlstarlet sel -t -m "Configuration/System/Network" -v @hostname -o ',' -v @uiAddress -n "$LAST_CONFIG" 2>/dev/null)"
    INFO_NETWORK+=",$(xmlstarlet sel -t -m "Configuration/System/Network/Ethernet/Adapter" -v @dev -o ',' -v @gateway -o ',' -v @name -o ',' -v @uuid -n "$LAST_CONFIG" 2>/dev/null)"
    INFO_NETWORK+=",$(xmlstarlet sel -t -m "Configuration/System/Network/Ethernet/Adapter/Address" -v . -n "$LAST_CONFIG" 2>/dev/null)"
    INFO_NETWORK+=",$(xmlstarlet sel -t -m "Configuration/System/Network/DNS/Server" -v . -n "$LAST_CONFIG" 2>/dev/null | xargs)"

    if [ -z "$INFO_NETWORK" ]; then
        echo 'Network info is empty'
        return 11
    fi

    INFO_EMAIL="$(xmlstarlet sel -t -m "Configuration/System/EmailIdentities" -v @admin -o ',' -v @messageManagement -o ',' -v @server -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$INFO_EMAIL" ]; then
        echo 'Email info is empty'
        return 12
    fi

    INFO_ALERT="$(xmlstarlet sel -t -m "Configuration/System/EngineAlerts" -v @recipient -o ',' -v @sender -o ',' -v @subject -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$INFO_ALERT" ]; then
        echo 'Alert info is empty'
        return 13
    fi

    KEYMAP="$(xmlstarlet sel -t -m "Configuration/System/OS" -v @keymap -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$KEYMAP" ]; then
        echo 'Keymap is empty'
        return 14
    fi

    LIST_PEER="$(xmlstarlet sel -t -m "Configuration/System/PeerAppliances/Peer" -v @address -o ',' -v @name -o ',' -v @password -o ',' -v @uuid -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$LIST_PEER" ]; then
        echo 'Peer list is empty'
        return 15
    fi

    COUNT_SCANNER="$(xmlstarlet sel -t -m "Configuration/ScannerSelection" -v @count -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$COUNT_SCANNER" ]; then
        echo 'Scanner count is empty'
        return 16
    fi

    LIST_SCANNER="$(xmlstarlet sel -t -m "Configuration/ScannerSelection/Scanner" -v @behavioural -o ',' -v @cloud -o ',' -v @enabled -o ',' -v @heuristic -o ',' -v @mnemonic -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$LIST_SCANNER" ]; then
        echo 'Scanner list is empty'
        return 17
    fi

    INFO_DEPLOYMENT="$(xmlstarlet sel -t -m "Configuration/Deployment" -v @admin -o ',' -v @adminName -o ',' -v @deployed -o ',' -v @file -o ',' -v @host -o ',' -v @ip -o ',' -v @planned -o ',' -v @pushSummaryStatus -o ',' -v @reason -o ',' -v @remote -o ',' -v @sourceHost -o ',' -v @state -n "$LAST_CONFIG" 2>/dev/null)"

    if [ -z "$INFO_DEPLOYMENT" ]; then
        echo 'Deployment info is empty'
        return 18
    fi

    COUNT_DEPLOYMENT="$(xmlstarlet sel -t -m "DeploymentRecords" -v @count -n "$DEPLOYMENT_HISTORY")"

    if [ -z "$COUNT_DEPLOYMENT" ]; then
        echo 'Deployment count is empty'
        return 19
    fi

    while read ADDRESS; do
        sed -i "/^  <AddressList color=\"#bcda6a\" name=\"My Company\"/a\ \ \ <Address>$ADDRESS</Address>" "$TEMPLATE_CONFIG"
    done < <(echo "$LIST_ADDRESS")

    sed -i "/^  <IcapSettings port=\"1344\"/i\ \ <VPNSettings allow_grace_period_renewal=\"$(echo $INFO_VPN | awk -F, '{print $1}')\" block_internet_access=\"$(echo $INFO_VPN | awk -F, '{print $2}')\" external_address=\"$(echo $INFO_VPN | awk -F, '{print $3}')\" feature_enabled=\"$(echo $INFO_VPN | awk -F, '{print $4}')\" grace_period=\"$(echo $INFO_VPN | awk -F, '{print $5}')\" max_grace_period_renewal_times=\"$(echo $INFO_VPN | awk -F, '{print $6}')\" network_adapter_uuid=\"$(echo $INFO_VPN | awk -F, '{print $7}')\" psk=\"$(echo $INFO_VPN | awk -F, '{print $8}')\" remote_connector_port=\"$(echo $INFO_VPN | awk -F, '{print $9}')\"/>" "$TEMPLATE_CONFIG"

    while read ENDPOINT; do
        sed -i "/^ <\/TLSEndPointCollection>/i\ \ <TLSEndPoint name=\"$(echo $ENDPOINT | awk -F, '{print $1}')\" relayControl=\"$(echo $ENDPOINT | awk -F, '{print $2}')\" useclientforserver=\"false\" uuid=\"$(echo $ENDPOINT | awk -F, '{print $3}')\">\n\ \ \ <Outbound certificateValidation=\"$(echo $ENDPOINT | awk -F, '{print $4}')\" certificateValidationUserString=\"$(echo $ENDPOINT | awk -F, '{print $5}')\" cipherStrength=\"$(echo $ENDPOINT | awk -F, '{print $6}')\" enableMandatoryTls=\"$(echo $ENDPOINT | awk -F, '{print $7}')\" useGlobalCipherStrength=\"$(echo $ENDPOINT | awk -F, '{print $8}')\" useGlobalTlsVersion=\"$(echo $ENDPOINT | awk -F, '{print $9}')\" useTls10=\"$(echo $ENDPOINT | awk -F, '{print $10}')\" useTls11=\"$(echo $ENDPOINT | awk -F, '{print $11}')\" useTls12=\"$(echo $ENDPOINT | awk -F, '{print $12}')\" uuid=\"$(uuidgen)\"/>\n\ \ \ <Inbound certificateCnMatch=\"$(echo $ENDPOINT | awk -F, '{print $13}')\" certificateIssuerCnMatch=\"$(echo $ENDPOINT | awk -F, '{print $14}')\" checkCertCn=\"$(echo $ENDPOINT | awk -F, '{print $15}')\" checkCertIssuerCn=\"$(echo $ENDPOINT | awk -F, '{print $16}')\" enableMandatoryTls=\"$(echo $ENDPOINT | awk -F, '{print $17}')\" encryptionStrengthBits=\"$(echo $ENDPOINT | awk -F, '{print $18}')\" requireValidCertificate=\"$(echo $ENDPOINT | awk -F, '{print $19}')\" uuid=\"$(uuidgen)\"/>\n\ \ \ <Auth authEnabled=\"false\" authPassword=\"\" authUser=\"\" uuid=\"$(uuidgen)\"/>\ \ \ \n\ \ \ <HostList enable=\"false\">" "$TEMPLATE_CONFIG"
        for HOST in $(echo "$ENDPOINT" | awk -F, '{print $20}'); do
            sed -i "/^ <\/TLSEndPointCollection>/i\ \ \ \ <Host>$HOST</Host>" "$TEMPLATE_CONFIG"
        done
        sed -i "/^ <\/TLSEndPointCollection>/i\ \ \ </HostList>\n\ \ \ <DomainList/>\n\ \ </TLSEndPoint>" "$TEMPLATE_CONFIG"
    done < <(echo "$LIST_ENDPOINT")

    sed -i "/^ <SmtpSettings>/a\ \ <Administrator>$ADMIN</Administrator>\n\ \ <Welcome>$WELCOME</Welcome>" "$TEMPLATE_CONFIG"

    while read DOMAIN; do
        sed -i "/^  <\/ManagedDomains>/i\ \ \ <Domain dkim_enabled=\"false\" dkim_formattedKey=\"\" dkim_keyAlias=\"\" dkim_keySelector=\"\" dkim_privateKey=\"\" dkim_publicKey=\"\" name=\"\" uuid=\"$(echo $DOMAIN | awk -F, '{print $2}')\">$(echo $DOMAIN | awk -F, '{print $1}')</Domain>" "$TEMPLATE_CONFIG"
    done < <(echo "$LIST_DOMAIN")

    sed -i "/^  <InternalHosts enable=\"false\"\/>/a\ \ <RoutingTable count=\"$(expr $COUNT_ROUTE + 2)\">" "$TEMPLATE_CONFIG"

    while read ROUTE; do
        sed -i "/^  <RoutingTable count=/a\ \ \ <Route domain=\"$(echo $ROUTE | awk -F, '{print $1}')\" routingType=\"$(echo $ROUTE | awk -F, '{print $2}')\" tlsEndpointUuid=\"$(echo $ROUTE | awk -F, '{print $3}')\">\n\ \ \ \ <SmptAuth authEnabled=\"false\" authPassword=\"\" authUser=\"\" uuid=\"$(uuidgen)\"/>\n\ \ \ \ <Server address=\"\" allowUntrusted=\"true\" name=\"\" port=\"25\" requireSecure=\"false\" uuid=\"$(uuidgen)\"/>\n\ \ \ \ <MtaGroup mtaGroupUuid=\"00000000-0000-0000-0000-000000000000\" port=\"25\"/>\n\ \ \ </Route>" "$TEMPLATE_CONFIG"
    done < <(echo "$LIST_ROUTE")

    sed -i "/^  <\/Network>/i\ <System uuid=\"$(uuidgen)\">\n\ \ <Network hostname=\"$(echo $INFO_NETWORK | awk -F, '{print $1}')\" uiAddress=\"$(echo $INFO_NETWORK | awk -F, '{print $2}')\">\n\ \ \ <Ethernet>\n\ \ \ \ <Adapter dev=\"$(echo $INFO_NETWORK | awk -F, '{print $3}')\" gateway=\"$(echo $INFO_NETWORK | awk -F, '{print $4}')\" name=\"$(echo $INFO_NETWORK | awk -F, '{print $5}')\" uuid=\"$(echo $INFO_NETWORK | awk -F, '{print $6}')\">\n\ \ \ \ \ <Address>$(echo $INFO_NETWORK | awk -F, '{print $7}')</Address>\n\ \ \ \ </Adapter>\n\ \ \ </Ethernet>\n\ \ \ <DNS dnsType=\"1\" searchPath=\"\" useroot=\"false\">" "$TEMPLATE_CONFIG"
    for DNS_SERVER in $(echo $INFO_NETWORK | awk -F, '{print $8}'); do
        sed -i "/^  <\/Network>/i\ \ \ \ <Server>$DNS_SERVER</Server>\n\ \ \ \ <StaticHosts/>" "$TEMPLATE_CONFIG"
    done
    sed -i "/^  <\/Network>/i\ \ \ </DNS>\n\ \ \ <StaticRoutes/>" "$TEMPLATE_CONFIG"

    sed -i "/^  <MessageAuditing enabled=\"true\"\/>/i\ \ <EmailIdentities admin=\"$(echo $INFO_EMAIL | awk -F, '{print $1}')\" messageManagement=\"$(echo $INFO_EMAIL | awk -F, '{print $2}')\" server=\"$(echo $INFO_EMAIL | awk -F, '{print $3}')\"/>\n\ \ <EngineAlerts enabled=\"true\" recipient=\"$(echo $INFO_ALERT | awk -F, '{print $1}')\" sender=\"$(echo $INFO_ALERT | awk -F, '{print $2}')\" subject=\"$(echo $INFO_ALERT | awk -F, '{print $3}')\"/>" "$TEMPLATE_CONFIG"

    sed -i "/^  <\/LexicalDataImportSettings>/a\ \ <OS keymap=\"$KEYMAP\"/>" "$TEMPLATE_CONFIG"

    while read PEER; do
        sed -i "/^  <PeerAppliances>/a\ \ \ <Peer address=\"$(echo $PEER | awk -F, '{print $1}')\" name=\"$(echo $PEER | awk -F, '{print $2}')\" password=\"$(echo $PEER | awk -F, '{print $3}')\" pushStatus=\"Unknown\" uuid=\"$(echo $PEER | awk -F, '{print $4}')\">\n\ \ \ \ <WhatAmI manufacturer=\"Clearswift\" productParentType=\"None\" productType=\"Smtp\" whatAmIType=\"EmailGateway\"/>\n\ \ \ \ <PMMPeer authenticationMethod=\"ntlm\" digestGenerator=\"false\" mobileAuthTimeout=\"6\" mobileEnabled=\"false\" mobilePort=\"443\" portalEnabled=\"false\" protocol=\"http\">\n\ \ \ \ \ <PortalAdapter dev=\"\" gateway=\"\" name=\"\" uuid=\"$(uuidgen)\"/>\n\ \ \ \ </PMMPeer>\n\ \ \ \ <ManagementRoles emailAudit=\"false\" icapAudit=\"false\" webAudit=\"false\" webAuditV4=\"false\"/>\n\ \ \ </Peer>" "$TEMPLATE_CONFIG"
    done < <(echo "$LIST_PEER")

    sed -i "/^ <\/ScannerSelection>/i\ <ScannerSelection count=\"$COUNT_SCANNER\">" "$TEMPLATE_CONFIG"
    while read SCANNER; do
        sed -i "/^ <\/ScannerSelection>/i\ \ <Scanner behavioural=\"$(echo $SCANNER | awk -F, '{print $1}')\" cloud=\"$(echo $SCANNER | awk -F, '{print $2}')\" enabled=\"$(echo $SCANNER | awk -F, '{print $3}')\" heuristic=\"$(echo $SCANNER | awk -F, '{print $4}')\" mnemonic=\"$(echo $SCANNER | awk -F, '{print $5}')\"/>" "$TEMPLATE_CONFIG"
    done < <(echo "$LIST_SCANNER")

    CONFIG_UUID="$(uuidgen)"
    CONFIG_WHEN="$(date +%s)000"
    CONFIG_WHENDESC="$(date +'%d %B %Y %T %Z')"

    sed -i "/^ <AuditDB changesMade=/a\ <Deployment admin=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $1}')\" adminName=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $2}')\" deployed=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $3}')\" file=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $4}')\" host=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $5}')\" ip=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $6}')\" planned=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $7}')\" pushSummaryStatus=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $8}')\" reason=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $9}')\" remote=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $10}')\" sourceHost=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $11}')\" state=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $12}')\" uuid=\"$CONFIG_UUID\" when=\"$CONFIG_WHEN\" whenDesc=\"$CONFIG_WHENDESC\"><Detail>Generated with create_config.sh</Detail>" "$TEMPLATE_CONFIG"

    FILE_CONFIG="/var/cs-gateway/deployments/$CONFIG_UUID.xml"

    mv -f "$TEMPLATE_CONFIG" "$FILE_CONFIG"
    chown cs-tomcat:cs-adm "$FILE_CONFIG"
    chmod g+w "$FILE_CONFIG"

    sed -i "s/<DeploymentRecords count=\"$COUNT_DEPLOYMENT\">/<DeploymentRecords count=\"$(expr $COUNT_DEPLOYMENT + 1)\"><Deployment admin=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $1}')\" adminName=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $2}')\" deployed=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $3}')\" file=\"$(echo $FILE_CONFIG | sed 's/\//\\\//g')\" host=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $5}')\" ip=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $6}')\" planned=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $7}')\" pushSummaryStatus=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $8}')\" reason=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $9}')\" remote=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $10}')\" sourceHost=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $11}')\" state=\"$(echo $INFO_DEPLOYMENT | awk -F, '{print $12}')\" uuid=\"$CONFIG_UUID\" when=\"$CONFIG_WHEN\" whenDesc=\"$CONFIG_WHENDESC\"><Progress current=\"89\" total=\"90\"\/><Log>log<\/Log><Detail>Generated with create_config.sh<\/Detail><PeerAppliances\/><ReferencePeers imageManager=\"none\" trustedSenders=\"none\"\/><SelectedAreas maintenance=\"false\" network=\"false\" peers=\"false\" pmm=\"false\" policy=\"false\" proxy=\"false\" reports=\"false\" systemConfig=\"false\" tlsCertificates=\"false\" users=\"false\"\/><\/Deployment>/" "$DEPLOYMENT_HISTORY"

    cs-servicecontrol restart tomcat &>/dev/null
}
# generate base policy
# parameters:
# none
# return values:
# none
generate_policy() {
    RESULT="$(create_config)"
    [ "$?" = 0 ] || $DIALOG --backtitle 'Manage configuration' --title 'Error generating base policy' --clear --msgbox "Error: $RESULT" 0 0
}
# toggle password check for cs-admin
# parameters:
# none
# return values:
# none
toggle_password() {
    if grep -q 'cs-admin ALL=(ALL) NOPASSWD:ALL' /etc/sudoers && grep -q '^\s*sudo su -s' /opt/csrh/cli/climenu; then
        STATUS_CURRENT='disabled'
        STATUS_TOGGLE='Enable'
    else
        STATUS_CURRENT='enabled'
        STATUS_TOGGLE='Disable'
    fi
    $DIALOG --backtitle 'Clearswift Configuration' --title 'Toggle CS admin password check' --yesno "CS admin password check is currently $STATUS_CURRENT. $STATUS_TOGGLE?" 0 60
    if [ "$?" = 0 ]; then
        if [ $STATUS_CURRENT = 'disabled' ]; then
            sed -i '/cs-admin ALL=(ALL) NOPASSWD:ALL/d' /etc/sudoers
            sed -i '/^\s*sudo su -s/s/sudo su -s/su -s/g' /opt/csrh/cli/climenu
        else
            grep -q 'cs-admin ALL=(ALL) NOPASSWD:ALL' /etc/sudoers || echo 'cs-admin ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
            sed -i '/^\s*su -s/s/su -s/sudo su -s/g' /opt/csrh/cli/climenu
        fi
    fi
}
# toggle mqueue cleanup
# parameters:
# none
# return values:
# none
toggle_cleanup() {
    PACKED_SCRIPT='
    H4sIAL8b3FsAA22PS0vDQBSF9/MrrkkXLZpM2pUoBUMbasEICnElhMn0JhnM3KnzUIP43w0+cOPi
    wIHD98GJT3ijiDfC9YzFIAcUttbPAQOmroeHZZqlGYunaWOOo1Vd72EuF7DKludwi35jCCryaAl7
    jeQatMIH6mCnm+szIPTSUDLFhcEr6lJp9JcuD7439gJKYSVsFdonhwRznR5++tW/7IKx7f6+Lu+q
    oirWEX8RlkuXdMLjqxi5Fmrg7mjMwL9P1CZ4HrEy39/U+a5YrxhrFR0gmv1pIkj8eERoIdFeaYTT
    aPYLTBu+oQSrIWnh/QMeL9knhMlH1DQBAAA=
    '
    if [ -f "$CRON_CLEANUP" ]; then
        STATUS_CURRENT='enabled'
        STATUS_TOGGLE='Disable'
    else
        STATUS_CURRENT='disabled'
        STATUS_TOGGLE='Enable'
    fi
    $DIALOG --backtitle 'Clearswift Configuration' --title 'Toggle CS mqueue cleanup' --yesno "CS mqueue cleanup is currently $STATUS_CURRENT. $STATUS_TOGGLE?" 0 60
    if [ "$?" = 0 ]; then
        if [ $STATUS_CURRENT = 'disabled' ]; then
            printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > $CRON_CLEANUP
            chmod 700 $CRON_CLEANUP
        else
            rm -f $CRON_CLEANUP
        fi
    fi
}
# toggle config email backup
# parameters:
# none
# return values:
# none
toggle_backup() {
    PACKED_SCRIPT='
    H4sIADK3pFwAA5WTUW/aMBDH3/0pbilrQCxJqbSHdUJqlkKHBrQCOmlqWWQSk1jEdmSbFrruu+8o
    3RooL0NBcs73v/vd5e7oXTDjMphRkxNyBExQXsQzmiyWpW9y+N7yT/wTcoRXkSrXmme5hXrSgNOT
    1icYMhspCTfSMi1ZLpg0M6apXcoMLsXs6weQzCZKevg3y8JymfmJEs/hwqXNlT6DAdUJXHCmF4ZJ
    qAs/fTmfH9Q2COmH40kcXQ27vcu2G9xTHSTGy6hlD3QdpKws1BpJrAkKamxYlgVnKWLOebZENq6k
    vxKFSyajcDi+vhpN4kF4jYEwW1AqY+d85amlnamlTAOrqTSl0tYXtHQJ6QzCXj8edaLeda8znLTd
    ON4zxbFLhuGgE38Jo283GDgax8lzdrwgF+GkE0c3o9FG7NTqKWJD83234RDS7fX/qZzAijKoVQLV
    qlL0Tkrw5uDUKt1w8LUSxCHZIy/3beJ+q6sY/exxT+rPFrtAzbaLtk0BV1jusNIBLIIluUL9XiOc
    J6APC/C6zrkD7q9Sc2mhdvrbxVpfPPvhj7brktst0c4HcWAKx8dQccREmWZYz8/aPgQ4sKuGbe5q
    VviLA+7t3R0+06m7j4UgjwjymvQgRcozaBocXgtNqVJpDEtArOAt1hOYjZcnNR4tbhZ4rQNomJnP
    4VDyz2BzJgngb9vkiEqpLKQMN05wyWCzr6BZQdfO1m3FLbQIKwyryG6jsbdd6ilEY9jOI8y1ErA7
    V0j3HNEz/yPyxmCELdtV+rPTj3ihoVbPcakkFaxx/noGL22AR/eG88AQkTknRIs3M+uQP5UHMWq6
    BAAA
    '
    if [ -f "$CRON_BACKUP" ]; then
        STATUS_CURRENT='enabled'
        STATUS_TOGGLE='Disable'
    else
        STATUS_CURRENT='disabled'
        STATUS_TOGGLE='Enable'
    fi
    $DIALOG --backtitle 'Clearswift Configuration' --title 'Toggle config email backup' --yesno "CS config email backup $STATUS_CURRENT. $STATUS_TOGGLE?" 0 60
    if [ "$?" = 0 ]; then
        if [ $STATUS_CURRENT = 'disabled' ]; then
            exec 3>&1
            DIALOG_RET="$(dialog --clear --backtitle 'Clearswift Configuration' --title 'Config email backup' --inputbox 'Enter email for CS config backup' 0 50 $EMAIL_DEFAULT 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
                printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > $CRON_BACKUP
                sed -i "s/__EMAIL_RECIPIENT__/$DIALOG_RET/" $CRON_BACKUP
                chmod 700 $CRON_BACKUP
            fi
        else
            rm -f $CRON_BACKUP
        fi
    fi
}
# add IP address for mail.intern zone in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_mail() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Manage mail.intern access' --title 'Add mail server IP to mail.intern' --inputbox 'Enter mail server IP for mail.intern' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        if [ ! -f $CONFIG_BIND ] || ! grep -q '^zone "intern" {' $CONFIG_BIND; then
            echo 'zone "intern" {' >> $CONFIG_BIND
        	echo '    type master;' >> $CONFIG_BIND
	        echo '    file "intern.db";' >> $CONFIG_BIND
            echo '};' >> $CONFIG_BIND
        fi
        if [ ! -f $CONFIG_INTERN ]; then
            echo '$ttl 38400' > $CONFIG_INTERN
            echo 'intern.  IN SOA		localhost. master.intern. (' >> $CONFIG_INTERN
            echo '		2017112200' >> $CONFIG_INTERN
            echo '		10800' >> $CONFIG_INTERN
            echo '		3600' >> $CONFIG_INTERN
            echo '		604800' >> $CONFIG_INTERN
            echo '		38400)' >> $CONFIG_INTERN
            echo 'intern.			IN	NS	ns1.intern.' >> $CONFIG_INTERN
            echo 'ns1			IN	A	127.0.0.1' >> $CONFIG_INTERN
        fi
        echo "mail	5	IN	A   $DIALOG_RET" >> $CONFIG_INTERN
        return 0
    else
        return 1
    fi
}
# add/remove IP addresses for mail.intern zone in dialog menu
# parameters:
# none
# return values:
# none
mail_intern() {
    while true; do
        LIST_IP=''
        [ -f $CONFIG_INTERN ] && LIST_IP=$(grep '^mail' $CONFIG_INTERN | awk '{print $5}')
        if [ -z "$LIST_IP" ]; then
            add_mail || break
        else
            ARRAY_INTERN=()
            for IP_ADDRESS in $LIST_IP; do
                ARRAY_INTERN+=($IP_ADDRESS '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Manage configuration' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove IPs for mail.intern' 0 0 0 "${ARRAY_INTERN[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_mail
            else
                if [ $RET_CODE = 3 ]; then
                    sed -i "/^mail.*$DIALOG_RET/d" $CONFIG_INTERN
                else
                    break
                fi
            fi
        fi
    done
    rndc reload
}
# add zone name and IP in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_forward() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Internal DNS forwarding' --title 'Add zone for internal DNS forwarding' --inputbox 'Enter zone name' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        ZONE_NAME="$DIALOG_RET"
        exec 3>&1
        DIALOG_RET="$(dialog --clear --backtitle 'Internal DNS forwarding' --title 'Add zone for internal DNS forwarding' --inputbox 'Enter IPs (space separated)' 0 50 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
            echo "zone \"$ZONE_NAME\" {" >> $CONFIG_BIND
            echo '    type forward;' >> $CONFIG_BIND
            echo "    forwarders { "$(for IP_ADDR in $DIALOG_RET; do echo "$IP_ADDR;"; done)" };" >> $CONFIG_BIND
            echo '    forward only;' >> $CONFIG_BIND
            echo '};' >> $CONFIG_BIND
            sed -i -E 's/dnssec-validation (auto|yes);/dnssec-validation no; # disabled because of internal forward zones/' $CONFIG_BIND
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}
# add/remove zones for internal DNS forwarding in dialog menu
# parameters:
# none
# return values:
# none
internal_forwarding() {
    while true; do
        LIST_FORWARD=''
        if [ -f $CONFIG_BIND ]; then
            ZONE_NAME=''
            while read LINE; do
                if echo "$LINE" | grep -q '^zone ".*" {$'; then
                    ZONE_NAME="$(echo $LINE | awk 'match($0, /^zone "(.*)" {$/, a) {print a[1]}')"
                fi
                if ! [ -z "$ZONE_NAME" ] && echo "$LINE" | grep -q '^\s*forwarders { .* };$'; then
                    LIST_FORWARD+=" $ZONE_NAME("$(echo $LINE | awk 'match($0, /forwarders { (.*); };$/, a) {print a[1]}' | sed 's/; /,/g')")"
                    ZONE_NAME=''
                fi
            done < <(sed -n '/^zone ".*" {$/,/^}$/p' $CONFIG_BIND)
        fi
        if [ -z "$LIST_FORWARD" ]; then
            add_forward || break
        else
            ARRAY_ZONE=()
            for ZONE_FORWARD in $LIST_FORWARD; do
                ARRAY_ZONE+=($ZONE_FORWARD '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Manage configuration' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove zones for internal DNS forwarding' 0 0 0 "${ARRAY_ZONE[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_forward
            else
                if [ $RET_CODE = 3 ]; then
                    sed -i "/zone \"$(echo $DIALOG_RET | awk -F\( '{print $1}')\" {/,/^}/d" $CONFIG_BIND
                    grep -q '^\s*forwarders { .* };$' $CONFIG_BIND || sed -i 's/dnssec-validation no; # disabled because of internal forward zones/dnssec-validation auto;/' $CONFIG_BIND
                else
                    break
                fi
            fi
        fi
    done
    rndc reload
}
# add email address for monthly reports in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_report() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Monthly email stats reports' --title 'Add recipient email for report' --inputbox 'Enter recipient email for monthly reports' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        echo "$SCRIPT_STATS $DIALOG_RET" >> $CRON_STATS
        return 0
    else
        return 1
    fi
}
# add/remove email addresses for monthly reports in dialog menu
# parameters:
# none
# return values:
# none
monthly_report() {
    while true; do
        LIST_EMAIL=""
        [ -f $CRON_STATS ] && LIST_EMAIL=$(grep "^$SCRIPT_STATS" $CRON_STATS | awk '{print $2}')
        if [ -z "$LIST_EMAIL" ]; then
            add_report || break
        else
            ARRAY_EMAIL=()
            for EMAIL_ADDRESS in $LIST_EMAIL; do
                ARRAY_EMAIL+=("$EMAIL_ADDRESS" '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Email recipients' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove emails for monthly email stats reports' 0 0 0 "${ARRAY_EMAIL[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_report
            else
                if [ $RET_CODE = 3 ]; then
                    sed -i "/$(echo "$SCRIPT_STATS $DIALOG_RET" | sed 's/\//\\\//g')/d" $CRON_STATS
                else
                    break
                fi
            fi
        fi
    done
}
# add email address for sender anomaly alerts in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_alert() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Sender anomaly detection' --title 'Add recipient email for anomaly alert'  \
        --inputbox 'Enter recipient email for anomaly alert' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        echo "30 1,7,13,19 * * * root $SCRIPT_ANOMALY $DIALOG_RET" >> $CRON_ANOMALY
        return 0
    else
        return 1
    fi
}
# add/remove email addresses for sender anomaly alerts in dialog menu
# parameters:
# none
# return values:
# none
anomaly_detect() {
    while true; do
        LIST_EMAIL=""
        [ -f $CRON_ANOMALY ] && LIST_EMAIL=$(grep "^30 1,7,13,19 \* \* \* root $SCRIPT_ANOMALY" $CRON_ANOMALY | awk '{print $8}')
        if [ -z "$LIST_EMAIL" ]; then
            add_alert || break
        else
            ARRAY_ADDR=()
            for EMAIL_ADDRESS in $LIST_EMAIL; do
                ARRAY_ADDR+=("$EMAIL_ADDRESS" '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Email recipients' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove emails for monthly email stats reports' 0 0 0 "${ARRAY_ADDR[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_alert
            else
                if [ $RET_CODE = 3 ]; then
                    sed -i "/$(echo "30 1,7,13,19 \* \* \* root $SCRIPT_ANOMALY $DIALOG_RET" | sed 's/\//\\\//g')/d" $CRON_ANOMALY
                else
                    break
                fi
            fi
        fi
    done
}
# get status of defined recipient validation
# parameters:
# $1 - validation
# return values:
# recipient validation status
check_enabled_validation() {
    [ -f "$PF_IN" ] && LINE_VALIDATION="$(grep 'smtpd_recipient_restrictions=' "$PF_IN")"
    if echo "$LINE_VALIDATION" | grep -q "$1"; then
        echo on
    else
        echo off
    fi
}
# get status of unverified_recipient recipient validation
# parameters:
# none
# return values:
# unverified_recipient recipient validation status
check_enabled_unverified_recipient() {
    if [ -f "$PF_IN" ]                                                                                  \
        && grep 'smtpd_recipient_restrictions=' "$PF_IN" | grep -q 'unverified_recipient'               \
        && grep -q 'address_verify_transport_maps=hash:/etc/postfix-outbound/transport.map' "$PF_IN"    \
        && grep -q 'address_verify_map=' "$PF_IN"                                                       \
        && grep -q "unverified_recipient_reject_reason=User doesn't exist" "$PF_IN"                     \
        && [ -f "$PF_OUT" ]                                                                             \
        && grep -q 'address_verify_map=' "$PF_OUT"; then
        echo on
    else
        echo off
    fi
}
# enable extra options for unverified_recipient recipient validation
# parameters:
# none
# return values:
# none
enable_unverified_recipient() {
    for OPTION in                                                                   \
        'address_verify_transport_maps=hash:/etc/postfix-outbound/transport.map'    \
        'address_verify_map='                                                       \
        "unverified_recipient_reject_reason=User doesn't exist"; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
    for OPTION in                                                                   \
        'address_verify_map='; do
        if ! [ -f "$PF_OUT" ] || ! grep -q "$OPTION" "$PF_OUT"; then
            echo "$OPTION" >> "$PF_OUT"
        fi
        postmulti -i postfix-outbound -x postconf "$OPTION"
    done
}
# disable extra options for unverified_recipient recipient validation
# parameters:
# none
# return values:
# none
disable_unverified_recipient() {
    for OPTION in                                                                   \
        'address_verify_transport_maps=hash:/etc/postfix-outbound/transport.map'    \
        'address_verify_map='                                                       \
        "unverified_recipient_reject_reason=\"User doesn't exist\""; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
    for OPTION in                                                                   \
        'address_verify_map='; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_OUT"
    done
}
# enable extra options for recipient validation
# parameters:
# none
# return values:
# none
enable_validation() {
    for OPTION in                                                                   \
        'smtpd_delay_reject=yes'                                                    \
        'smtpd_helo_required=yes'; do
        if ! [ -f "$PF_IN" ] || ! grep -q "$OPTION" "$PF_IN"; then
            echo "$OPTION" >> "$PF_IN"
        fi
        postmulti -i postfix-inbound -x postconf "$OPTION"
    done
}
# disable extra options for recipient validation
# parameters:
# none
# return values:
# none
disable_validation() {
    for OPTION in                                                                   \
        'smtpd_delay_reject=yes'                                                    \
        'smtpd_helo_required=yes'; do
        sed -i "/$(echo "$OPTION" | sed 's/\//\\\//g')/d" "$PF_IN"
    done
}
# select recipient validation to enable in dialog checkbox
# parameters:
# none
# return values:
# none
recipient_validation() {
    VALIDATION_ENABLED=''
    for VALIDATION in unknown_client invalid_hostname non_fqdn_hostname unknown_reverse_client_hostname non_fqdn_helo_hostname   \
        invalid_helo_hostname unknown_helo_hostname non_fqdn_sender unknown_sender_domain unknown_recipient_domain               \
        non_fqdn_recipient unauth_pipelining; do
        declare DIALOG_${VALIDATION^^}="$VALIDATION"
        STATUS_VALIDATION="$(check_enabled_validation $VALIDATION)"
        declare STATUS_${VALIDATION^^}="$STATUS_VALIDATION"
        [ "$STATUS_VALIDATION" = 'on' ] && VALIDATION_ENABLED=1
    done
    declare DIALOG_UNVERIFIED_RECIPIENT='unverified_recipient'
    STATUS_VALIDATION="$(check_enabled_unverified_recipient)"
    declare STATUS_UNVERIFIED_RECIPIENT="$STATUS_VALIDATION"
    [ "$STATUS_VALIDATION" = 'on' ] && VALIDATION_ENABLED=1
    exec 3>&1
    DIALOG_RET="$($DIALOG --clear --backtitle 'Clearswift configuration' --cancel-label 'Back'          \
        --ok-label 'Apply' --checklist 'Choose recipient rejection criteria' 0 0 0                      \
        "$DIALOG_UNKNOWN_CLIENT" ''                   "$STATUS_UNKNOWN_CLIENT"                          \
        "$DIALOG_INVALID_HOSTNAME" ''                 "$STATUS_INVALID_HOSTNAME"                        \
        "$DIALOG_NON_FQDN_HOSTNAME" ''                "$STATUS_NON_FQDN_HOSTNAME"                       \
        "$DIALOG_UNKNOWN_REVERSE_CLIENT_HOSTNAME" ''  "$STATUS_UNKNOWN_REVERSE_CLIENT_HOSTNAME"         \
        "$DIALOG_NON_FQDN_HELO_HOSTNAME" ''           "$STATUS_NON_FQDN_HELO_HOSTNAME"                  \
        "$DIALOG_INVALID_HELO_HOSTNAME" ''            "$STATUS_INVALID_HELO_HOSTNAME"                   \
        "$DIALOG_UNKNOWN_HELO_HOSTNAME" ''            "$STATUS_UNKNOWN_HELO_HOSTNAME"                   \
        "$DIALOG_NON_FQDN_SENDER" ''                  "$STATUS_NON_FQDN_SENDER"                         \
        "$DIALOG_UNKNOWN_SENDER_DOMAIN" ''            "$STATUS_UNKNOWN_SENDER_DOMAIN"                   \
        "$DIALOG_UNKNOWN_RECIPIENT_DOMAIN" ''         "$STATUS_UNKNOWN_RECIPIENT_DOMAIN"                \
        "$DIALOG_NON_FQDN_RECIPIENT" ''               "$STATUS_NON_FQDN_RECIPIENT"                      \
        "$DIALOG_UNAUTH_PIPELINING" ''                "$STATUS_UNAUTH_PIPELINING"                       \
        "$DIALOG_UNVERIFIED_RECIPIENT" ''             "$STATUS_UNVERIFIED_RECIPIENT"                    \
        2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        LIST_ENABLED=''
        MODIFIED=''
        for VALIDATION in unknown_client invalid_hostname non_fqdn_hostname unknown_reverse_client_hostname non_fqdn_helo_hostname   \
            invalid_helo_hostname unknown_helo_hostname non_fqdn_sender unknown_sender_domain unknown_recipient_domain               \
            non_fqdn_recipient unauth_pipelining; do
            if echo "$DIALOG_RET" | grep -q "$(eval echo '$'DIALOG_${VALIDATION^^})"; then
                LIST_ENABLED+=", reject_$VALIDATION"
                [ "$(eval echo '$'STATUS_${VALIDATION^^})" = 'off' ] && MODIFIED=1
            else
                [ "$(eval echo '$'STATUS_${VALIDATION^^})" = 'on' ] && MODIFIED=1
            fi
        done
        if echo "$DIALOG_RET" | grep -q "$DIALOG_UNVERIFIED_RECIPIENT"; then
            LIST_ENABLED+=', reject_unverified_recipient'
            if [ "$STATUS_UNVERIFIED_RECIPIENT" = 'off' ]; then
                enable_unverified_recipient
                MODIFIED=1
            fi
        else
            if [ "$STATUS_UNVERIFIED_RECIPIENT" = 'on' ]; then
                disable_unverified_recipient
                MODIFIED=1
                APPLY_NEEDED=1
            fi
        fi
        if [ "$MODIFIED" = 1 ]; then
            [ -f "$PF_IN" ] && sed -i '/smtpd_recipient_restrictions=/d' "$PF_IN"
            if [ -z "$LIST_ENABLED" ]; then
                disable_validation
                APPLY_NEEDED=1
            else
                [ -z "$VALIDATION_ENABLED" ] && enable_validation
                LIST_ENABLED="smtpd_recipient_restrictions=check_client_access cidr:/etc/postfix/maps/check_client_access_ips, check_sender_access regexp:/etc/postfix/maps/check_sender_access, check_recipient_access regexp:/etc/postfix/maps/check_recipient_access, check_helo_access regexp:/etc/postfix/maps/check_helo_access$LIST_ENABLED"
                echo "$LIST_ENABLED" >> "$PF_IN"
            fi
            if [ "$APPLY_NEEDED" = 1 ]; then
                $DIALOG --backtitle "Clearswift configuration" --title 'Recipient restrictions' --clear --msgbox 'Recipient restrictions changed.'$'\n\n''IMPORTANT: Apply configuration in main menu.' 0 0
            else
                postmulti -i postfix-inbound -x postconf "$LIST_ENABLED"
                postfix stop &>/dev/null
                postfix start &>/dev/null
            fi
        fi
    fi
}
###################################################################################################
# write some example config files
###################################################################################################
# write example configuration files
# parameters:
# none
# return values:
# none
write_examples() {
    [ -d "$DIR_MAPS" ] || mkdir -p "$DIR_MAPS"
    if ! [ -f "$WHITELIST_POSTSCREEN" ]; then
        echo '######################################################################' >> "$WHITELIST_POSTSCREEN"
        echo '# IPs vom postscreen ausschliessen, Whitelisten (Monitoring Systeme) #' >> "$WHITELIST_POSTSCREEN"
        echo '######################################################################' >> "$WHITELIST_POSTSCREEN"
        echo '#NetCon (CIDR)' >> $WHITELIST_POSTSCREEN
        echo '#88.198.215.226 permit' >> $WHITELIST_POSTSCREEN
        echo '#85.10.249.206  permit' >> $WHITELIST_POSTSCREEN
    fi
    if ! [ -f "$WHITELIST_POSTFIX" ]; then
        echo '############################################################' >> "$WHITELIST_POSTFIX"
        echo '# IP-Adressen erlauben, die ein seltsames Verhalten zeigen #' >> "$WHITELIST_POSTFIX"
        echo '############################################################' >> "$WHITELIST_POSTFIX"
        echo '# Postfix IP Whitelist (CIDR)' >> "$WHITELIST_POSTFIX"
        echo '#1.2.3.4  REJECT unwanted newsletters!' >> "$WHITELIST_POSTFIX"
        echo '#1.2.3.0/24  OK' >> "$WHITELIST_POSTFIX"
    fi
    if ! [ -f "$SENDER_ACCESS" ]; then
        echo '##########################################' >> "$SENDER_ACCESS"
        echo '# Postfix Sender Email Blacklist (REGEXP)#' >> "$SENDER_ACCESS"
        echo '# bestimmte Domains von Extern ablehnen  #' >> "$SENDER_ACCESS"
        echo '##########################################' >> "$SENDER_ACCESS"
        echo '#/.*@isdoll\.de$/    REJECT mydomain in your envelope sender not allowed! Use your own domain!' >> "$SENDER_ACCESS"
    fi
    if ! [ -f "$RECIPIENT_ACCESS" ]; then
        echo '#############################################' >> "$RECIPIENT_ACCESS"
        echo '# Postfix Recipient Email Blacklist (REJECT)#' >> "$RECIPIENT_ACCESS"
        echo '# bestimmte Empfaenger ablehnen             #' >> "$RECIPIENT_ACCESS"
        echo '#############################################' >> "$RECIPIENT_ACCESS"
        echo '#/mueller@isdoll\.de$/    REJECT user has moved!' >> "$RECIPIENT_ACCESS"
    fi
    if ! [ -f "$HELO_ACCESS" ]; then
        echo '#######################################' >> "$HELO_ACCESS"
        echo '# Postfix Helo Blacklist (REGEXP)     #' >> "$HELO_ACCESS"
        echo '# HELO String des Mailservers pruefen #' >> "$HELO_ACCESS"
        echo '#######################################' >> "$HELO_ACCESS"
    fi
    if ! [ -f "$ESMTP_ACCESS" ]; then
        echo '##################################' >> "$ESMTP_ACCESS"
        echo '# Postfix ESMTP Verbs            #' >> "$ESMTP_ACCESS"
        echo '# remove unnecessary ESMTP Verbs #' >> "$ESMTP_ACCESS"
        echo '##################################' >> "$ESMTP_ACCESS"
        echo '#130.180.71.126/32      silent-discard, auth' >> "$ESMTP_ACCESS"
        echo '#212.202.158.254/32     silent-discard, auth' >> "$ESMTP_ACCESS"
        echo '#0.0.0.0/0              silent-discard, etrn, enhancedstatuscodes, dsn, pipelining, auth' >> "$ESMTP_ACCESS"
    fi
    if ! [ -f "$HEADER_REWRITE" ]; then
        echo '#####################################' >> "$HEADER_REWRITE"
        echo '# Postfix Outbound Header Rewriting #' >> "$HEADER_REWRITE"
        echo '#####################################' >> "$HEADER_REWRITE"
        echo '#/^\s*Received: from \S+ \(\S+ \[\S+\]\)(.*)/ REPLACE Received: from [127.0.0.1] (localhost [127.0.0.1])$1' >> "$HEADER_REWRITE"
        echo '#/^\s*User-Agent/        IGNORE' >> "$HEADER_REWRITE"
        echo '#/^\s*X-Enigmail/        IGNORE' >> "$HEADER_REWRITE"
        echo '#/^\s*X-Mailer/          IGNORE' >> "$HEADER_REWRITE"
        echo '#/^\s*X-Originating-IP/  IGNORE' >> "$HEADER_REWRITE"
    fi
    if ! [ -f "$SENDER_REWRITE" ]; then
        echo '#############################' >> "$SENDER_REWRITE"
        echo '# fix broken sender address #' >> "$SENDER_REWRITE"
        echo '#############################' >> "$SENDER_REWRITE"
        echo '#/^<.*>(.*)@(.*)>/   ${1}@${2}' >> "$SENDER_REWRITE"
    fi
    if ! [ -f "$SENDER_ROUTING" ]; then
        echo '############################' >> "$SENDER_ROUTING"
        echo '# sender dependent routing #' >> "$SENDER_ROUTING"
        echo '############################' >> "$SENDER_ROUTING"
        echo '#mueller@isdoll.de     smtp:[127.0.0.1]:10026' >> "$SENDER_ROUTING"
        echo '#@isdoll.de            smtp:[127.0.0.1]:10026' >> "$SENDER_ROUTING"
        postmap "$SENDER_ROUTING"
    fi
}
###################################################################################################
# select Postfix configuration to edit in dialog menu
# parameters:
# none
# return values:
# none
dialog_postfix() {
    DIALOG_WHITELIST_POSTFIX='Postfix whitelist'
    DIALOG_WHITELIST_POSTSCREEN='Postscreen whitelist'
    DIALOG_ESMTP_ACCESS='ESMTP access'
    DIALOG_SENDER_ACCESS='Sender access'
    DIALOG_RECIPIENT_ACCESS='Recipient access'
    DIALOG_HELO_ACCESS='HELO access'
    DIALOG_SENDER_REWRITE='Sender rewrite'
    DIALOG_HEADER_REWRITE='Header rewrite'
    DIALOG_SENDER_ROUTING='Sender dependent routing'
    DIALOG_RESTRICTIONS='Postfix restrictions'
    DIALOG_BACKUP='Backup Postfix feature config'
    DIALOG_RESTORE='Restore Postfix feature config'
    while true; do
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN"                                 \
            --cancel-label 'Back' --ok-label 'Edit' --menu 'Manage Postfix configuration' 0 0 0 \
            "$DIALOG_WHITELIST_POSTFIX" ''                                                      \
            "$DIALOG_WHITELIST_POSTSCREEN" ''                                                   \
            "$DIALOG_ESMTP_ACCESS" ''                                                           \
            "$DIALOG_SENDER_ACCESS" ''                                                          \
            "$DIALOG_RECIPIENT_ACCESS" ''                                                       \
            "$DIALOG_HELO_ACCESS" ''                                                            \
            "$DIALOG_SENDER_REWRITE" ''                                                         \
            "$DIALOG_HEADER_REWRITE" ''                                                         \
            "$DIALOG_SENDER_ROUTING" ''                                                         \
            "$DIALOG_RESTRICTIONS" ''                                                           \
            "$DIALOG_BACKUP" ''                                                                 \
            "$DIALOG_RESTORE" ''                                                                \
            2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_WHITELIST_POSTFIX")
                    "$TXT_EDITOR" "$WHITELIST_POSTFIX";;
                "$DIALOG_WHITELIST_POSTSCREEN")
                    "$TXT_EDITOR" "$WHITELIST_POSTSCREEN";;
                "$DIALOG_ESMTP_ACCESS")
                    "$TXT_EDITOR" "$ESMTP_ACCESS";;
                "$DIALOG_SENDER_ACCESS")
                    "$TXT_EDITOR" "$SENDER_ACCESS";;
                "$DIALOG_RECIPIENT_ACCESS")
                    "$TXT_EDITOR" "$RECIPIENT_ACCESS";;
                "$DIALOG_HELO_ACCESS")
                    "$TXT_EDITOR" "$HELO_ACCESS";;
                "$DIALOG_SENDER_REWRITE")
                    "$TXT_EDITOR" "$SENDER_REWRITE";;
                "$DIALOG_HEADER_REWRITE")
                    "$TXT_EDITOR" "$HEADER_REWRITE";;
                "$DIALOG_SENDER_ROUTING")
                    "$TXT_EDITOR" "$SENDER_ROUTING"
                    postmap "$SENDER_ROUTING";;
                "$DIALOG_RESTRICTIONS")
                    dialog_restrictions;;
                "$DIALOG_BACKUP")
                    cp -r "$PF_IN" "$BACKUP_IN"
                    cp -r "$PF_OUT" "$BACKUP_OUT";;
                "$DIALOG_RESTORE")
                    cp -r "$BACKUP_IN" "$PF_IN"
                    cp -r "$BACKUP_OUT" "$PF_OUT"
                    $DIALOG --backtitle "$TITLE_MAIN" --title 'Postfix feature config restore' --clear --msgbox 'Postfix feature config restored.'$'\n\n''Apply configuration in main menu.' 0 0
                    APPLY_NEEDED=1;;
            esac
        else
            break
        fi
    done
}
# select restriction option to manage in dialog menu
# parameters:
# none
# return values:
# none
dialog_restrictions() {
    DIALOG_RECIPIENT='Recipient restrictions'
    while true; do
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Edit' \
            --menu 'Manage Postfix restrictions' 0 0 0 "$DIALOG_RECIPIENT" '' 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_RECIPIENT")
                    recipient_validation;;
            esac
        else
            break
        fi
    done
}
# select Clearswift configuration to manage in dialog menu
# parameters:
# none
# return values:
# none
dialog_clearswift() {
    DIALOG_INSTALL_COMMAND='Install external command'
    DIALOG_EDIT_COMMAND='Edit external command'
    DIALOG_LDAP='LDAP schedule'
    DIALOG_SSH='SSH access'
    DIALOG_SMTP='SMTP block'
    DIALOG_KEY_AUTH='SSH key authentication for cs-admin'
    DIALOG_IMPORT_KEYSTORE='Import PKCS12 for Tomcat'
    DIALOG_EXPORT_ADDRESS='Export and email address lists'
    DIALOG_RULE='Import policy rule'
    DIALOG_SAMPLE='Email sample config'
    DIALOG_POLICY='Generate base policy'
    DIALOG_TOGGLE_PASSWORD='CS admin password check'
    DIALOG_TOGGLE_CLEANUP='Mqueue cleanup'
    DIALOG_TOGGLE_BACKUP='Email config backup'
    while true; do
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN"                                    \
            --cancel-label 'Back' --ok-label 'Edit' --menu 'Manage Clearswift configuration' 0 0 0 \
            "$DIALOG_INSTALL_COMMAND" ''                                                           \
            "$DIALOG_EDIT_COMMAND" ''                                                              \
            "$DIALOG_LDAP" ''                                                                      \
            "$DIALOG_SSH" ''                                                                       \
            "$DIALOG_SMTP" ''                                                                      \
            "$DIALOG_KEY_AUTH" ''                                                                  \
            "$DIALOG_IMPORT_KEYSTORE" ''                                                           \
            "$DIALOG_EXPORT_ADDRESS" ''                                                            \
            "$DIALOG_RULE" ''                                                                      \
            "$DIALOG_SAMPLE" ''                                                                    \
            "$DIALOG_POLICY" ''                                                                    \
            "$DIALOG_TOGGLE_PASSWORD" ''                                                           \
            "$DIALOG_TOGGLE_CLEANUP" ''                                                            \
            "$DIALOG_TOGGLE_BACKUP" ''                                                             \
            2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_INSTALL_COMMAND")
                    install_command;;
                "$DIALOG_EDIT_COMMAND")
                    cd $DIR_COMMANDS
                    $TXT_EDITOR .
                    cd -;;
                "$DIALOG_LDAP")
                    ldap_schedule;;
                "$DIALOG_SSH")
                    ssh_access;;
                "$DIALOG_SMTP")
                    smtp_block;;
                "$DIALOG_KEY_AUTH")
                    key_auth;;
                "$DIALOG_IMPORT_KEYSTORE")
                    import_keystore;;
                "$DIALOG_EXPORT_ADDRESS")
                    export_address_list;;
                "$DIALOG_RULE")
                    import_rule;;
                "$DIALOG_SAMPLE")
                    email_sample;;
                "$DIALOG_POLICY")
                    generate_policy;;
                "$DIALOG_TOGGLE_PASSWORD")
                    toggle_password;;
                "$DIALOG_TOGGLE_CLEANUP")
                    toggle_cleanup;;
                "$DIALOG_TOGGLE_BACKUP")
                    toggle_backup;;
            esac
        else
            break
        fi
    done
}
# check whether master-slave cluster is enabled
# parameters:
# none
# return values:
# master-slave cluster status
check_enabled_cluster() {
    if [ -f "$CONFIG_OPTIONS" ] && grep -q '^neighbours {$' "$CONFIG_OPTIONS" && grep -q '^dynamic_conf = "/var/lib/rspamd/rspamd_dynamic";$' "$CONFIG_OPTIONS"; then
        echo on
    else
        echo off
    fi
}
# check whether sender whitelist management is enabled
# parameters:
# none
# return values:
# sender whitelist management status
check_enabled_sender() {
    if [ -f "$CRON_SENDER" ]; then
        echo on
    else
        echo off
    fi
}
# check whether disabling greylisting is enabled
# parameters:
# none
# return values:
# greylisting status
check_enabled_greylist() {
    if [ -f "$CONFIG_ACTIONS" ] && grep -q '^greylist = null;$' "$CONFIG_ACTIONS" && [ -f "$CONFIG_GREYLIST" ] && grep -q '^enabled = false;$' "$CONFIG_GREYLIST"; then
        echo on
    else
        echo off
    fi
}
# check whether disabling rejecting is enabled
# parameters:
# none
# return values:
# rejecting status
check_enabled_reject() {
    if [ -f "$CONFIG_ACTIONS" ] && grep -q '^reject = null;$' "$CONFIG_ACTIONS"; then
        echo on
    else
        echo off
    fi
}
# check whether bayes-learning is enabled
# parameters:
# none
# return values:
# bayes-learning status
check_enabled_bayes() {
    if [ -f "$CONFIG_BAYES" ] && grep -q '^autolearn = true;$' "$CONFIG_BAYES"; then
        echo on
    else
        echo off
    fi
}
# check whether detailed headers is enabled
# parameters:
# none
# return values:
# detailed headers status
check_enabled_headers() {
    if [ -f "$CONFIG_HEADERS" ] && grep -q '^extended_spam_headers = true;$' "$CONFIG_HEADERS"; then
        echo on
    else
        echo off
    fi
}
# check whether detailed history is enabled
# parameters:
# none
# return values:
# detailed history status
check_enabled_history() {
    if [ -f "$CONFIG_HISTORY" ] && grep -q '^servers = 127.0.0.1:6379;$' "$CONFIG_HISTORY"; then
        echo on
    else
        echo off
    fi
}
# check whether Spamassassin rules is enabled
# parameters:
# none
# return values:
# Spamassassin rules status
check_enabled_spamassassin() {
    if [ -f "$CONFIG_SPAMASSASSIN" ] && grep -q "^ruleset = \"$FILE_RULES\";$" "$CONFIG_SPAMASSASSIN"     \
        && grep -q '^alpha = 0.1;$' "$CONFIG_SPAMASSASSIN"; then
        echo on
    else
        echo off
    fi
}
# check whether URL reputation is enabled
# parameters:
# none
# return values:
# URL reputation status
check_enabled_reputation() {
    if [ -f "$CONFIG_REPUTATION" ] && grep -q '^enabled = true;$' "$CONFIG_REPUTATION"; then
        echo on
    else
        echo off
    fi
}
# check whether phishing detection is enabled
# parameters:
# none
# return values:
# phishing detection status
check_enabled_phishing() {
    if [ -f "$CONFIG_PHISHING" ] && grep -q '^phishtank_enabled = true;$' "$CONFIG_PHISHING"                              \
        && grep -q '^phishtank_map = "https://rspamd.com/phishtank/online-valid.json.zst";$' "$CONFIG_PHISHING"; then
        echo on
    else
        echo off
    fi
}
# check whether Pyzor is enabled
# parameters:
# none
# return values:
# Pyzor status
check_enabled_pyzor() {
    if [ -f "$CONFIG_LOCAL" ] && grep -q '^pyzor { }$' "$CONFIG_LOCAL"; then
        echo on
    else
        echo off
    fi
}
# check whether Razor is enabled
# parameters:
# none
# return values:
# Razor status
check_enabled_razor() {
    if [ -f "$CONFIG_LOCAL" ] && grep -q '^razor { }$' "$CONFIG_LOCAL"; then
        echo on
    else
        echo off
    fi
}
# check whether automatic rspamd update is enabled
# parameters:
# none
# return values:
# automatic rspamd update status
check_enabled_update() {
    if [ -f "$CRON_UPDATE" ]; then
        echo on
    else
        echo off
    fi
}
# check whether automatic spamassassin rules update is enabled
# parameters:
# none
# return values:
# automatic automatic spamassassin rules update status
check_enabled_rulesupdate() {
    if [ -f "$CRON_RULES" ]; then
        echo on
    else
        echo off
    fi
}
# check whether Elasticsearch logging is enabled
# parameters:
# none
# return values:
# Elasticsearch logging status
check_enabled_elastic() {
    if [ -f "$CONFIG_ELASTIC" ] && grep -q '^server = ' "$CONFIG_ELASTIC" && grep -q '^ingest_module = true;$' "$CONFIG_ELASTIC"    \
        && grep -q '^debug = true;$' "$CONFIG_ELASTIC" && grep -q '^import_kibana = true;$' "$CONFIG_ELASTIC"; then
        echo on
    else
        echo off
    fi
}
# enable master-slave cluster
# parameters:
# none
# return values:
# none
enable_cluster() {
    LIST_PEER="$(grep '<Peer address="' /var/cs-gateway/peers.xml | awk 'match($0, /<Peer address="([^"]+)" /, a) match($0, / name="([^"]+)" /, b) {print a[1]","b[1]}')"
    IP_MASTER="$(echo $LIST_PEER | awk '{print $1}' | awk -F, '{print $1}')"
    IP_SLAVE="$(echo $LIST_PEER | awk '{print $2}' | awk -F, '{print $1}')"
    HOST_NAME="$(hostname -f)"
    IP_OTHER="$(echo $LIST_PEER | xargs -n 1 | awk -F, "\$2 != \"$HOST_NAME\" {print \$1}")"
    HOSTNAME_OTHER="$(echo $LIST_PEER | xargs -n 1 | awk -F, "\$2 != \"$HOST_NAME\" {print \$2}")"
    CONFIG_REDIS='/etc/redis.conf'
    sed -i 's/^bind 127.0.0.1/#bind 127.0.0.1/' "$CONFIG_REDIS"
    sed -i 's/^protected-mode yes/protected-mode no/' "$CONFIG_REDIS"
    if [ "$HOST_NAME" == "$(echo $LIST_PEER | awk '{print $1}' | awk -F, '{print $2}')" ]; then
        echo 'write_servers = "127.0.0.1";' > "$CONFIG_RSPAMD_REDIS"
    else
        echo "write_servers = \"$IP_MASTER:6379\";" > "$CONFIG_RSPAMD_REDIS"
    fi
    echo 'read_servers = "127.0.0.1";' >> "$CONFIG_RSPAMD_REDIS"
    echo 'neighbours {'$'\n\t'"server1 { host = \"$IP_MASTER:11334\"; }"$'\n\t'"server2 { host = \"$IP_SLAVE:11334\"; }"$'\n''}' >> "$CONFIG_OPTIONS"
    echo 'dynamic_conf = "/var/lib/rspamd/rspamd_dynamic";' >> "$CONFIG_OPTIONS"
    echo 'backend = "redis";' > /etc/rspamd/local.d/classifier-bayes.conf
    echo 'backend = "redis";' > /etc/rspamd/local.d/worker-fuzzy.inc
    if ! [ -f $CONFIG_CONTROLLER ] || ! grep -q 'bind_socket = "*:11334";' "$CONFIG_CONTROLLER"; then
        echo 'bind_socket = "*:11334";' >> "$CONFIG_CONTROLLER"
    fi
    if [ ! -f $CONFIG_FW ] || ! grep -q "\-I INPUT 4 -i eth0 -p tcp --dport 11334 -s $IP_OTHER -j ACCEPT" $CONFIG_FW; then
        echo "-I INPUT 4 -i eth0 -p tcp --dport 11334 -s $IP_OTHER -j ACCEPT" >> $CONFIG_FW
        iptables -I INPUT 4 -i eth0 -p tcp --dport 11334 -s $IP_OTHER -j ACCEPT
    fi
    if [ ! -f $CONFIG_FW ] || ! grep -q "\-I INPUT 4 -i eth0 -p tcp --dport 6379 -s $IP_OTHER -j ACCEPT" $CONFIG_FW; then
        echo "-I INPUT 4 -i eth0 -p tcp --dport 6379 -s $IP_OTHER -j ACCEPT" >> $CONFIG_FW
        iptables -I INPUT 4 -i eth0 -p tcp --dport 6379 -s $IP_OTHER -j ACCEPT
    fi
    service rspamd restart &>/dev/null
}
# disable master-slave cluster
# parameters:
# none
# return values:
# none
disable_cluster() {
    LIST_PEER="$(grep '<Peer address="' /var/cs-gateway/peers.xml | awk 'match($0, /<Peer address="([^"]+)" /, a) match($0, / name="([^"]+)" /, b) {print a[1]","b[1]}')"
    HOST_NAME="$(hostname -f)"
    IP_OTHER="$(echo $LIST_PEER | xargs -n 1 | awk -F, "\$2 != \"$HOST_NAME\" {print \$1}")"
    CONFIG_REDIS='/etc/redis.conf'
    CONFIG_RSPAMD_REDIS='/etc/rspamd/local.d/redis.conf'
    sed -i 's/^#bind 127.0.0.1/bind 127.0.0.1/' "$CONFIG_REDIS"
    sed -i 's/^protected-mode no/protected-mode yes/' "$CONFIG_REDIS"
    rm -f "$CONFIG_RSPAMD_REDIS" /etc/rspamd/local.d/classifier-bayes.conf /etc/rspamd/local.d/worker-fuzzy.inc
    sed -i '/^neighbours {$/,/^}$/d' "$CONFIG_OPTIONS"
    sed -i '/dynamic_conf = "/var/lib/rspamd/rspamd_dynamic";/d' "$CONFIG_OPTIONS"
    sed -i '/bind_socket = "\*:11334";/d' "$CONFIG_CONTROLLER"
    sed -i "/-I INPUT 4 -i eth0 -p tcp --dport 11334 -s $IP_OTHER -j ACCEPT/d" $CONFIG_FW
    iptables -D INPUT -i eth0 -p tcp --dport 11334 -s $IP_OTHER -j ACCEPT
    sed -i "/-I INPUT 4 -i eth0 -p tcp --dport 6379 -s $IP_OTHER -j ACCEPT/d" $CONFIG_FW
    iptables -D INPUT -i eth0 -p tcp --dport 6379 -s $IP_OTHER -j ACCEPT
    service rspamd restart &>/dev/null
}
# enable sender whitelist management
# parameters:
# none
# return values:
# none
enable_sender() {
    printf "%s" $SENDER_SCRIPT | base64 -d | gunzip > $CRON_SENDER
    chmod 700 $CRON_SENDER
    $CRON_SENDER
}
# disable sender whitelist management
# parameters:
# none
# return values:
# none
disable_sender() {
    rm -f $CRON_SENDER
}
# enable disabling greylisting
# parameters:
# none
# return values:
# none
enable_greylist() {
    if ! [ -f "$CONFIG_ACTIONS" ] || ! grep -q 'greylist = null' "$CONFIG_ACTIONS"; then
        echo 'greylist = null;' >> "$CONFIG_ACTIONS"
    fi
    if ! [ -f "$CONFIG_GREYLIST" ] || ! grep -q 'enabled = false;' "$CONFIG_GREYLIST"; then
        echo 'enabled = false;' >> "$CONFIG_GREYLIST"
    fi
}
# disable disabling greylisting
# parameters:
# none
# return values:
# none
disable_greylist() {
    [ -f "$CONFIG_ACTIONS" ] && sed -i '/greylist = null;/d' "$CONFIG_ACTIONS"
    [ -f "$CONFIG_GREYLIST" ] && sed -i '/enabled = false;/d' "$CONFIG_GREYLIST"
}
# enable disabling rejecting
# parameters:
# none
# return values:
# none
enable_reject() {
    echo 'reject = null;' >> "$CONFIG_ACTIONS"
}
# disable disabling rejecting
# parameters:
# none
# return values:
# none
disable_reject() {
    sed -i '/reject = null;/d' "$CONFIG_ACTIONS"
}
# enable bayes
# parameters:
# none
# return values:
# none
enable_bayes() {
    echo 'autolearn = true;' >> "$CONFIG_BAYES"
}
# disable bayes
# parameters:
# none
# return values:
# none
disable_bayes() {
    sed -i '/autolearn = true;/d' "$CONFIG_BAYES"
}
# enable detailed headers
# parameters:
# none
# return values:
# none
enable_headers() {
    echo 'extended_spam_headers = true;' >> "$CONFIG_HEADERS"
}
# disable detailed headers
# parameters:
# none
# return values:
# none
disable_headers() {
    sed -i '/extended_spam_headers = true;/d' "$CONFIG_HEADERS"
}
# enable detailed history
# parameters:
# none
# return values:
# none
enable_history() {
    echo 'servers = 127.0.0.1:6379;' >> "$CONFIG_HISTORY"
}
# disable detailed history
# parameters:
# none
# return values:
# none
disable_history() {
    sed -i '/servers = 127.0.0.1:6379;/d' "$CONFIG_HISTORY"
}
# enable Spamassassin rules
# parameters:
# none
# return values:
# none
enable_spamassassin() {
    echo "ruleset = \"$FILE_RULES\";" >> "$CONFIG_SPAMASSASSIN"
    echo 'alpha = 0.1;' >> "$CONFIG_SPAMASSASSIN"
}
# disable Spamassassin rules
# parameters:
# none
# return values:
# none
disable_spamassassin() {
    sed -i "/$(echo "$FILE_RULES" | sed 's/\//\\\//g')/d" "$CONFIG_SPAMASSASSIN"
    sed -i '/alpha = 0.1;/d' "$CONFIG_SPAMASSASSIN"
}
# enable URL reputation
# parameters:
# none
# return values:
# none
enable_reputation() {
    echo 'enabled = true;' >> "$CONFIG_REPUTATION"
}
# disable URL reputation
# parameters:
# none
# return values:
# none
disable_reputation() {
    sed -i '/enabled = true;/d' "$CONFIG_REPUTATION"
}
# enable phishing detection
# parameters:
# none
# return values:
# none
enable_phishing() {
    echo 'phishtank_enabled = true;' >> "$CONFIG_PHISHING"
    echo 'phishtank_map = "https://rspamd.com/phishtank/online-valid.json.zst";' >> "$CONFIG_PHISHING"
}
# disable phishing detection
# parameters:
# none
# return values:
# none
disable_phishing() {
    sed -i '/phishtank_enabled = true;/d' "$CONFIG_PHISHING"
    sed -i '/phishtank_map = "https:\/\/rspamd.com\/phishtank\/online-valid.json.zst";/d' "$CONFIG_PHISHING"
}
# enable Pyzor
# parameters:
# none
# return values:
# none
enable_pyzor() {
    echo 'pyzor { }' >> "$CONFIG_LOCAL"
}
# disable Pyzor
# parameters:
# none
# return values:
# none
disable_pyzor() {
    sed -i '/pyzor { }/d' "$CONFIG_LOCAL"
}
# enable Razor
# parameters:
# none
# return values:
# none
enable_razor() {
    echo 'razor { }' >> "$CONFIG_LOCAL"
}
# disable Razor
# parameters:
# none
# return values:
# none
disable_razor() {
    sed -i '/razor { }/d' "$CONFIG_LOCAL"
}
# enable automatic spamd updates
# parameters:
# none
# return values:
# none
enable_update() {
    PACKED_SCRIPT='
    H4sIAPnvtlwAA3WWa5OiSBaGv9evyHVqp7qDrQIVUGajZhu5iYgioCA9vR3cQW6SXBR39r8vdRmr
    L7UERCRw8jkvJ5M47y9/Q504Rx27im5ufgHN0bNr/yusjnbmPVQR2A0fxg/YzS/9O6Y4djAOoxp8
    cD+CETakwMqvmSIH27z2Ye5HmZ9Xjg/tuslDIGTO/B8g92u3yO/7q2rSOs7DB7fInnF0U0cF/A3I
    NnQBG/swqfwcfMgevNfxp3fnfry50VV6pSlrVf8q08rjHdqHoceiqoP4fF80tVM0uYfW0M6rYwHr
    h8w+3t3ccDItLr+qHCMqIrfSH++ak/+pqYos8+GD5/cRXZMBN/Ld5P6lCuClCuDX31HPb9G8SdOb
    OACfweD2XwPwt0eAgS//BHXk5zegPyoftrF7nVXVxfG7qU8xTyle4ffde/ynoLccP6Z4OhSakTj2
    q8aootJ/xfX5HK9EWlgJcHiiaXxoOAZqazMWCRR8tx2t+G6bC5rdYnqZF6Xn4uvdhmHk2NMbbCGY
    1YqvrKVXe8eCYNErNIDriZlXK0kqUGHeZpnj5VblYeNQW0L6gHdNgs+N2VQYYdqUEyo5xKdWnRr0
    zFW5cxeLFT9vGqNY0LZ1haqCyjJkoJMuE+DGEGWUYRTg9jg786RwUciMMTgT4ylbV7a6G7GZLmgI
    rxxNjZtGEOcy23VbURInhFZfoSOMIYcWKQ/hgsbZ3aK4iGaarHFHzNX5CsmlackF2BBz1aSGGavB
    cGdr+XDHzbP5Sq74/S47Q+YcdqNIvkLXvFtF8gpmJwXjS9SQtbHmMCmFBOxksbuI7WJhJOJxvWDH
    NjuVgoahnVo6MPxKEEx2x63g5MwUsUiTo/Kbmh614KwJAdyeyvmwrk76gSswaR7LRrVc7qe4u1ep
    haid97omV3Ea7+g8Hu7PC5LUoSeJDZ5tdlZC59M3pTHfCLtNnYZ6uUySrba91AV2WF9C2Q52nerj
    6Jk/5TYNF6YDW3lnCtP9pcUt3Zlg0cRtKJmuS7pFT26yuEKTGWKFc2WObU1sLLGJTo8QHkY2pxlO
    oBqSSfuWidpTDDO52NgEBEZYuZ6vLRYi3tyl0MvJHlfnFinkzRV62SPjE2tukFGCk0564Sa+Nk4I
    gRqtlgfZxMmAQ8i9uDak0ibXG8ysqoxKdZTgW7o7mbFdbMgL6eXT9UW8QlfZOpyT+9Bbjh3bxpuD
    Lg670hIZ1PJP23haNLSJL/NyKme+v5Au0pjZtYciXxRFEE48Za5E6dLabEMHqa7Q8XlLdBF3wA9z
    yafwwPPCUt9S8MS4iivhFgc1eYfQllKcqW5Tsl6KJ4KpOu5obm6cwAkv0DCsyXJLxukVisso03kj
    tV0uMVmSFTerjEOdsUyzIA2FwFZ0lKM4wfLUJDzNxel0OG/mDQsJLpxNoNcSCOoHzhAPkNa4QpGD
    Buekf8HMg9Ge6jk1UXxLG1NtIq4tvjSEQ2Ksoc+NjgIN/T2+kJbJ9BRY5GZ7wJyCx9kkMiZR0Zli
    fIUaUKAspK3PBkoz2lDM8Gi0TdxFiRzHFpUJGC/S+/2pK+a8K7cnPBRmSpU2TJlQ29omJy63Og9J
    Nc0P1PEKbYJjl2xHXHzK1eFWTNt1bbuB7aDSFhX4qBwLTIksNt00Cfcqkze2dRg53XbNJ1rt8KK4
    ZkzPUoMmQsfRFcpKNivPusDYEdi66/ylN/RlnDiPN+dSQrdGRVliJWLkmRwdtlIO5bGKr2bR0TmV
    lE2rErGj9+2MIDpjMrxCQ8ax16WnTlNF0PWtbgW61OiyQ0hUKW4vzMhDglk54sMlr48ChzBDa7fe
    LYMFvzoqjgIneqdALd1lfmpfoZNdiZLHsxMrKctRExEX1ptE9sOTlHH1mVKWqcoggjnzTDbapHts
    xe7Z/RkViazOah6/zGdTZLjGcCfD3lafGrUGv1v369dcdpSgEbV/QANbao3SaBGUdxo+8rwllewP
    kw1zCmXXDKOWgQRBpefkIi8JZ2me68PKsf0r1J8ih0VApNNqEhlbXyPWCDYihjzh8LIHIZ27o5ka
    1Et3Eu3sbOqdSmWPqKjQLAO7piuaph8fr7C3LnWEcV4HYPD3agBuv2tl4E/QmxCfxMG914/DJr/E
    R/A7eO7ucR7XDx760jBvrjSZ0zRa4L4+9/bHgfraeRvX9asq6Ptp99ptPVAXoPVhFfdu5e72w1Mf
    TuOq/qsF9/mgf3y7s08JuPvPs1hwO/rv3ce7wXNSP638/5P9joOwgC/5eqvyynr58iB+3yHYsP6p
    +7PrHrf6xqgMbj/4blT0juAHCzN40XnPDz4Nvlf7IvY1eknvH+9edHwG933tb7/zTwPwBfz667fB
    fcLnagz+ffujGNCv2nez36kV+EsWuPv8xx/9+eXL3XvyejGXXsxb4neVeHEIkKo3ijVA8sLLq8p3
    QXYGP0v7E1RPUfc57Ie1HafgfvjeUg7eTNbPAn4wWy+FZ+w8L2rg+b3LzeLcB9kTHfY/djd4Cz3H
    NRj+vEte1+67zTLodT0z7isw+PyybV9N5xfwY+i9BqqsPj5+q/S3EdG/gOD2Q9T73tzO/I+f3sb9
    H/Txne3y11bsz/8B3xJ0NvYLAAA=
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > $CRON_UPDATE
    chmod 700 $CRON_UPDATE
}
# disable automatic spamd updates
# parameters:
# none
# return values:
# none
disable_update() {
    rm -f $CRON_UPDATE
}
# enable Spamassassin rules update
# parameters:
# none
# return values:
# none
enable_rulesupdate() {
    PACKED_SCRIPT='
    H4sIAOxMtFwAA41UbXOiSBD+zq/oNdmYnCcgvu/VphYRFUVN8N2rqxTC8BJhGGEQtfbHH2IuFytb
    dUcxBTM9/fTTz/T0zRdu42Juo0cOw9xATEydopcw9lDERg7MS6zA8sxNapICcgxd26FwbzyAwJea
    MEJUCjDMMEUhRo6PcLRBoU5jbEPX3/R+B4yoEeBiOqLYoy62WSPwMzgxpk4QfoOhHhrQdlG4jRCG
    e5813/5//NL3gWHaivaizVR58j3PUZ9w0+FTxjfPdBRVfjel3lwYEd03OS8wdI81ufNMj6L0dTH7
    5sPMZW2ijEdvfrnbe9O1gR4oCGyFLbNXPg5ysZeOYhQTEoSUNREUojQPCj+BhlA0IZ/LP+QYxrXg
    TyieIHd7hZ+Dv/4A6iDMQPogwwkgL+kYBxRMlKrouxjBRISMHOxRGLkBzl82H1wKJcZymUue7fFi
    pI7Fdkr5XRHuOhpL7dOFy5czGytlc+V6zcbfmm6aAoEPgLnMEvpn5w9hfsuWjTj0oFiMXA9hCjmH
    UvKN45Ik+U/RPvHUQzalmoIFMSUx/USUyQL+z0Q+Sxsk2At0813Z/L/7zqoK2fSs7PmbkoGidKUC
    FA+nz0Gz3R/p/HPEcHcHBvls+Dh7SQstvWpQ+Np5uCAZOr3SmDUseLxGuBB8EqWB3H6ZSJryNP1+
    yaVXiRRR7AtRJxHF8mLCL3btYWvSrZeFwfOgy3caVbO+UJJFv/SqToluSvymI021oKILs+VgEmnL
    NV84jJr+QM0A1ecTbQ5b/YRYDQUZXHdVVlru9EhEiWirynYXv7YGgeQr8tZoNeLeQpP2nMw3mo1+
    pbqrvWpNVd4dStJ8RrwM8FR1ukrPtA6D3qhGK2ve1tXaeLbtW+3WDHXoSl7X1bl4mkoaHkpTnhvO
    T1rTFseFQTWQiRp13LWF13Kd9usZoFIrJdQ/uOiptOWJsGlJs+pQOgRkR6INT5YWOjbXs7h53OvP
    SUl+nRvW2HELRFB6wXBkDruLncYtk+XTqNHKAOflmfLsCcbY49YaHVKj7pREedlfnpZbiz/VhJOC
    muU9SvjCYrlvd6nuz5Nwu7YTLihMjiuv11+txqpfo2EtA2zpHrLr1UC0RTFbuJwVCV1M09r4GuXg
    9uow0y6SdmJUq5w7yU+wY3xyCTz+sgoiFO5dA8Glx0GIorRwKdw9cibaczj2vHOv+BukmnrV4AUA
    AA==
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > $CRON_RULES
    chmod 700 $CRON_RULES
    $CRON_RULES
}
# disable Spamassassin rules update
# parameters:
# none
# return values:
# none
disable_rulesupdate() {
    rm -f $CRON_RULES
}
# enable Elasticsearch logging
# parameters:
# $1 - Elasticsearch host IP
# return values:
# none
enable_elastic() {
    local DIALOG_RET RET_CODE ELASTIC_HOST

    if [ -z "$1" ]; then
        exec 3>&1
        DIALOG_RET="$(dialog --clear --backtitle 'Enable features' --title 'Elasticsearch logging'   \
            --inputbox 'Enter IP address of Elasticsearch host' 0 50 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
            ELASTIC_HOST="$DIALOG_RET"
        else
            return 1
        fi
    else
        ELASTIC_HOST="$1"
    fi
    echo "server = \"$ELASTIC_HOST:9200\";" >> "$CONFIG_ELASTIC"
    echo 'ingest_module = true;' >> "$CONFIG_ELASTIC"
    echo 'debug = true;' >> "$CONFIG_ELASTIC"
    echo 'import_kibana = true;' >> "$CONFIG_ELASTIC"
}
# disable Elasticsearch logging
# parameters:
# $1 - Elasticsearch host IP
# return values:
# none
disable_elastic() {
    sed -i "/^server = \"$1:9200\";/d" "$CONFIG_ELASTIC"
    sed -i '/ingest_module = true;/d' "$CONFIG_ELASTIC"
    sed -i '/debug = true;/d' "$CONFIG_ELASTIC"
    sed -i '/import_kibana = true;/d' "$CONFIG_ELASTIC"
}
# check whether Pyzor and Razor are installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_pyzorrazor() {
    which pyzor &>/dev/null
    PYZOR_INSTALLED="$?"
    which razor-check &>/dev/null
    RAZOR_INSTALLED="$?"
    if [ "$PYZOR_INSTALLED" = 0 ] && [ "$RAZOR_INSTALLED" = 0 ]; then
        return 0
    else
        return 1
    fi
}
# install Pyzor and Razor plugins
# parameters:
# none
# return values:
# none
install_pyzorrazor() {
    if check_installed_pyzorrazor; then
        confirm_reinstall 'Pyzor & Razor' || return
    fi

    clear
    yum install -y python34-setuptools python34-devel perl-Razor-Agent
    python3 /usr/lib/python3.4/site-packages/easy_install.py pip
    pip3 install pyzor
    PACKED_SCRIPT='
    H4sIAANBq1wAA5VVbW/TMBD+TH6FFWlqKnVRWiiISt2XDQkJ2CaEQLypcpJrGpbaxXZUyrT/zp2d
    95UKug+L7+55fL7XQia8YGVSsCVT8LPMFTAfj75XWE0hswxUV6n0jm/TlVPUZibZHbFBqe9VFteo
    93eH37LB6MM2lsXKykh5+/nLzftaKXdGE6MjSqRY59kiA7PiRbFCZXA99rzzc3YFa14WhmkwJheZ
    ruDJOlttpDbEO529CCP8m/od5U4qUs5fzp8Sz71/+9FfMH+GVhPmX8oU7DGK6Pjp7fmlLIUhUeT0
    1Wn+lI4fNgp46s7Pps9JdJXzjAQ3b/yHOgTrUiQml4IlG0ju3MMDw/Xd2GP4GxrFASg1YSk33BnQ
    L18zlDKzAdHIHJjSEaLul6VEFygbgCFAmVQLdqbRL/we93AKTKlaKhCpN6BMIS6zbXA9YY53RA4R
    3QglGGKFYQ+sk5iRFktv2XGlbfFgQYXuEIwHNvLOeoVGzmBh/60q3uEFnTAIaRD8T5GwEbD8SIVP
    1jspNPxHSAY+E0PrMFWljH9AYh49br/JDRS5NpCivZGi3MYYA8J/bavq+xCmgMrzGKYBDLOUi7Vs
    3puQ1fJMs32xtG+sCSddjzok2Ejv+B20Ws0sB+OsyI0pgMW5Cfvmhxgo+ApGGs1i7D9M9Z4f0GWs
    lD5ZLlDIE8s56dLEJd5hWAEcC9VscjTVTMst4LfI2hs7EWk+z7uPGaZoD3m2oQ6PvG7RNOCLJZtG
    0ePqaXDTcN6WQKFhAJ7NT2JnJ8GnsdEp6JRxkfbrCt94gi8KZ8dLGYkro4tjBFRKixzbRJkV1h7O
    2KA7sCcVeMJcg4ZrqbbcBHXtpbb20r/W3vjRyGmcq3vATa8lu29M/cvXry7ffBN+W0PWTepAXBEG
    BLag0z3UXEdnmI/c6kDDwG2kqhVwX4XVvcF97wrqREI2wmq51HumVVSLpd4xrUJvSpPKvSAqVUKr
    oNFWLU/oMmEUipgndHcSu0eNPRslTJ3dj03SKkFoveqlsrMIG4sm3F2o9fsRtHpNY9HPVH87K8go
    t2rl6qQTQcG3gCy9+jn6zHYvTrwn5rAj1Kg2GKEsU7Kk0TvSeSY4zmnQoyY02C3dpLuR6OMY3Mq0
    xBlGG8P5ijgqzWsXzz/X6mWbBAkAAA==
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /usr/share/rspamd/plugins/pyzor.lua
    if ! [ -f "$CONFIG_LOCAL" ] || ! grep -q '^pyzor { }$' "$CONFIG_LOCAL"; then
        echo 'pyzor { }' >> "$CONFIG_LOCAL"
    fi
    groupadd pyzorsocket
    useradd -g pyzorsocket pyzorsocket
    mkdir -p /opt/pyzorsocket/bin/
    PACKED_SCRIPT='
    H4sIAGtBq1wAA3VUTY/TMBC951eYcHFEcYW4VeoBuistQitVtDdAloknrVvHDnba3YL474w/mmZL
    8SX2eN6b8byZvH41PXg3/aHMtDv1W2veF6rtrOuJcJtOOA/nM7RCaRZN7spmtapPZ5v1593OW1M0
    zrbE23oPPQKP4Ei+XS+Wq2iYkPXWgZDKbB7V8yczIasez+0X+HkA3z8IIzWGPLN2p1/WsVorMP1L
    m1Qb9C+KotbCe/IST2+RVrOiILgkNGQbTdSDbtBM8qpbSeYkGJlrlAYWMtXKAK2YhNpK3HydvX33
    fUCoJoHmpFw83C8+lxeysCJVisXrLdR7Wg33oD3c8H5yqgceqkl/l+CcdeWMlAezN/bJkNq2LdKV
    f6rrt2T+qxclBfFRY0HZx1MPfhn3NOk5H4vLVo/r5SXR1m+QIEPjh15KlPOIuURFgutIIHYnenEX
    txgMqSp2FPoAl5qHtAdQUpot4gernh6VqEah/qnUfkaOpLGO7Ce4USbRMnRoPa3G1RqhAsuEyFG5
    dphIuGLy0Haeyoq8IeU3U14Fjr0RieiOgUmNUQ29mDqdXjf6MAM5YIe+iAlJYfENzeYwipjGeSLZ
    B7c5tFiNrJcEXzvV9cqaeXn/3FkPqXbEGiLy8JXVQMWElFxkDlriyZUTsgXdzeMBMOHeEq1QIIMc
    /4eG4RugcRJv43zOPvVKIEAJkgAhIN7SYAvs+DtQSB2PgbHKft4d0S3XMfldzXJ0693poh1iWPzp
    cOwDCMDk1CgjtL7l6HitsXwhuQIHmXMjWuA8TjPnQRPO80AngYq/7vjOR0EFAAA=
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /opt/pyzorsocket/bin/pyzorsocket.py
    chown pyzorsocket:pyzorsocket /opt/pyzorsocket/bin/pyzorsocket.py
    chmod 0700 /opt/pyzorsocket/bin/pyzorsocket.py
    PACKED_SCRIPT='
    H4sIAIFHp1wAA5VSYU/qMBT9bH/FdSwoL9nKNETFkBdj5ot5vGAGmqgxppTCGqDdazvfQ/G/uxU2
    B+oHt0/33HPO7bltbRcPucBDomNUQzVIFs9SaUmnzNiaxlMqxZhP2uDBcQuCVgaOmKaKJ4ZL0d5U
    QKIkZVoLMmebrazXl6miDMapoLkUZnyoiFr4yAfMDMVccOOPcNHXCEXh4Oas22miq6j3q7NX8dtD
    3d7574vLbthx8BNReJbBWKdDvdDYzekOurq960X9jBYOHq/7YbRlgLQhyuw34AXB+mM0luAJcPp5
    i4sJWKs2OCVlRNhcCv7MwEuz7tYIwDIxuDLGbrdS+8kCgoMjv5n9AbROWoel8zqs+7NE7sFdgeCx
    v9CEB6jXwciUxuAW8TfOXhaKmVSJQo5e87Ay+SJrnBqbdST/iffAO1M+m+XXuYLAG4TRn0L83UOr
    OXjj7x+aEs3AcQMHuLA0e2WNUmHLsjo9XXNkUqXI5CODmFQ3tmHFPthXtJ/O+tHY3Kdzrckke/mr
    lb1YzTK3Wa5mLtczXt8fFPvPDQRVY6YJRRYuVvEGr04i2KYDAAA=
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /etc/init.d/pyzorsocket
    chmod +x /etc/init.d/pyzorsocket
    chkconfig --add pyzorsocket
    chkconfig pyzorsocket on
    service pyzorsocket start
    PACKED_SCRIPT='
    H4sIAAdCq1wAA4VUTWvbQBA9R79iEQRLoJg4lxJDDiUtFAou5FgKYiWNPvBq191d0bih/70zu6uv
    2KXywWLmzZuZNzMSquSCCdU0oNkT0/Bz6DSwWJsT76vcO+JIOJgtT1cwaI2jgDigP9b8t5pizLkv
    lMidjZwvH79/exmd6mQNMXqiUsm6a/YN2JwLkaMzOaRRdHfHPkHNB2GZAWs72ZgQXtZN3ipjiXf3
    8GF7j79dvHCelCbn4+7xYaywHmRpOyVZ2UJ59HUllptjGjF83oOKBLTOWMUt9wB6upqhldkW5GTz
    waTWFn2vjjJDLVAswArRpvSe3Zo4o/d0FafBDnqmAllFMyXVo8GQ8hZ71dh/clGOB6AMpGR8WRlV
    s++kAW1zxKKWyXIwGdtt79NrvVRQDE2fHDIWGnIJZigIA8v87dX0/yJrL7j+p+cgj1L9ki6hwn5Y
    rVXPXBNGlUewQWPypxeK0v9izONwntjbBI2fv3x+/vpDxtlkcuLRVuKCWpA2Sb3vz8h1vTnk1mec
    lq8O+3RovJZtyJu8rVLQgClyMobVHrd8doS1Hjd8dph2sBXJg1R6gCy6oU0JNwtLCmxfFLykpGUR
    2kkjpw+O093lNMVg2Lp6VrNdHOCEmIRehrqKL0JDHxNiPaP1V0FD0xkLOvd7u9BO8h6QZbXP0Y09
    n8i6GRvdoK3RaqA72piukRxvDszmuiTzt2HWZtzOMO9O1uo1iW8N61U1CGBSWeaLReIKd/DgBf0L
    bFL70WMFAAA=
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /usr/share/rspamd/plugins/razor.lua
    if ! [ -f "$CONFIG_LOCAL" ] || ! grep -q '^razor { }$' "$CONFIG_LOCAL"; then
        echo 'razor { }' >> "$CONFIG_LOCAL"
    fi
    groupadd razorsocket
    useradd -g razorsocket razorsocket
    mkdir -p /opt/razorsocket/bin/
    PACKED_SCRIPT='
    H4sIAHhCq1wAA31UUW/TMBB+Jr/CmIc6oktBvKBJfYBpaAhNqlh5GpPlJZfWm2MH29lWEP+ds+Ok
    WdXhl9iXu+/O932+N68XnbOLW6kX7c5vjf6QyaY11hNhN62wDoYzNEKqIprsgc0oWe4Gm3HD7s4Z
    Pexdd9taU4JzWW1NQ5wp78Ej1ANYknzWZ6uraJiT9daCqKTeXMqnr3pOrjyem+/wqwPnL4SuFBaR
    ZaUSzpHnZnbMNz/NMoKrgppso4k5UDWaSVplU5ElCcbC1lJBEQpQUgPLiwpKU+Hm+vTk/c0YIes+
    aEno2cX52Te6BwsrQvW5eLmF8p7l439QDo54P1rpgYe2sT8UrDWWnhLa6XttHjUpTdMgHP2bH94l
    4R/cqKcKLzVlrvi88+BWcc964pZTFoury/VqX2jjNgiQQuOH7VuU6girRi/TgmZ04Zt2sb5cWfEb
    y58T+kj3cOmKDGEL4bjzFilm+dShVAaTTKAtuE75wM0ooaIUSrFrOko3JjuJXQgpn9dwk2evpqQN
    gEvy7hkHPQWR+77K29AqNnOtaGZzMvux/nLycZb/h8WXELYHACN9E8JD7JxUE/7u8M7hV1F1TetY
    lZO3hP7UNHsx3V0BuldqPj6O/kWxwwc1vrWUsEVfjAlFoRo0S+YwBLCMYRYUn+yma0D7JKAKXGll
    66XRS3r+1CJ1JDadGE1EeuSJ/4BRiKriImEwiqcgkS2odhkPyC3xhijpPGjEeDk0DIwxNE6P43Eu
    Vd+LNwC4QVwhIf5lwRbQcexIhI7HgDgQ5ewDuqU+9n4HwyW6ebvbc4cxRRxuvDYWQmDvVEuN0j3m
    aPmo/AxFyrkWDXAexwvngRPO04TpCcr+AZfHVnq7BQAA
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /opt/razorsocket/bin/razorsocket.py
    chown razorsocket:razorsocket /opt/razorsocket/bin/razorsocket.py
    chmod 0700 /opt/razorsocket/bin/razorsocket.py
    PACKED_SCRIPT='
    H4sIAJxIq1wAA5VSXU/CMBR9tr/iOhYVk63MxKgYYoyZxojBDPRBY0wphTVAO9tORfG/uxU2B+qD
    29M993z03ra2iftc4D7RMaqhGijyLpWWdMyMrWk8plIM+agJHhzuQ7CfgQOmqeKJ4VI0VxWQKEmZ
    1oJM2Wor63VlqiiDYSpoLoUJ7yuiZj7yATNDMRfc+ANc9DVCUdi7O223Gugm6ly0tit+26jdObs6
    v2yHLQe/EIUnGYx12tczjd2c7qDo9L4TdTNa2Hu67YbRmgHShiizU4cPBMuP0ViCJ8Dp5i0uRmCt
    muCUlAFhUyn4OwMvBXc9ArBMDK7E2O1Waj+ZQbB34DeyP4Cj4GivdF4O656UyEMWYEHw2DM04BG2
    tsDIlMbgFuOvnL0sFDOpEoUcfebDyuSPWePU2FkH8lV8D7wx5pNJfp0LCLxeGF0X4v8eWk3BG/7/
    0JRoBo4bOMCFpdkrq5cKW5bV8fGSI5MqRSY/GcSkur4OK/bDvqL9NWu3vrpP51aTUfbyFyv7sJp5
    bjNfZM6XGZ/fD4q9cQNB1ZhpQpGFi1V8AdB9kzCmAwAA
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /etc/init.d/razorsocket
    chmod +x /etc/init.d/razorsocket
    chkconfig --add razorsocket
    chkconfig razorsocket on
    service razorsocket start
    service rspamd restart
    get_keypress
}
# reset Bayes spam database
# parameters:
# none
# return values:
# none
reset_bayes() {
    $DIALOG --clear --backtitle "$TITLE_MAIN $VERSION_MENU" --ok-label 'Ok' --cancel-label 'Cancel' --yesno 'Delete Bayes spam database?' 0 0
    if [ "$?" = 0 ]; then
        service rspamd stop &>/dev/null
        rm -f /var/lib/rspamd/bayes.spam.sqlite
        service rspamd start &>/dev/null
    fi
}
# add IP range for Rspamd web UI access in dialog inputbox
# parameters:
# none
# return values:
# error code - 0 for added, 1 for cancel
add_webui() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle 'Manage Rspamd web UI access' --title 'Add allowed IP/-range' --inputbox 'Enter allowed IP/-range for Rspamd web UI access' 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        echo "-I INPUT 4 -i eth0 -p tcp --dport 11334 -s $DIALOG_RET -j ACCEPT" >> $CONFIG_FW
        iptables -I INPUT 4 -i eth0 -p tcp --dport 11334 -s $DIALOG_RET -j ACCEPT
        if ! [ -f "$CONFIG_CONTROLLER" ] || ! grep -q 'bind_socket = "*:11334";' "$CONFIG_CONTROLLER"; then
            echo 'bind_socket = "*:11334";' >> "$CONFIG_CONTROLLER"
            service rspamd restart &>/dev/null
        fi
        return 0
    else
        return 1
    fi
}
# add/remove IP ranges for Rspamd web UI access in dialog menu
# parameters:
# none
# return values:
# none
webui_access() {
    while true; do
        LIST_IP=''
        [ -f $CONFIG_FW ] && LIST_IP=$(grep 'I INPUT 4 -i eth0 -p tcp --dport 11334 -s ' $CONFIG_FW | awk '{print $11}')
        if [ -z "$LIST_IP" ]; then
            add_webui || break
        else
            ARRAY_IP=()
            for IP_ADDRESS in $LIST_IP; do
                ARRAY_IP+=($IP_ADDRESS '')
            done
            exec 3>&1
            DIALOG_RET="$($DIALOG --clear --backtitle '' --title 'Manage configuration' --cancel-label 'Back' --ok-label 'Add' --extra-button --extra-label 'Remove'        \
                --menu 'Add/remove IPs for Rspamd web UI access' 0 0 0 "${ARRAY_IP[@]}" 2>&1 1>&3)"
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_webui
            else
                if [ $RET_CODE = 3 ]; then
                    IP_ADDRESS="$(echo "$DIALOG_RET" | sed 's/\//\\\//g')"
                    sed -i "/-I INPUT 4 -i eth0 -p tcp --dport 11334 -s $IP_ADDRESS -j ACCEPT/d" $CONFIG_FW
                    iptables -D INPUT -i eth0 -p tcp --dport 11334 -s $DIALOG_RET -j ACCEPT
                    if [ "$(echo $LIST_IP | wc -w)" = 1 ] && [ -f "$CONFIG_CONTROLLER" ]; then
                        sed -i '/bind_socket = "*:11334";/d' "$CONFIG_CONTROLLER"
                        service rspamd restart &>/dev/null
                    fi
                else
                    break
                fi
            fi
        fi
    done
}
# check for rspamd update and install it
# parameters:
# none
# return values:
# none
rspamd_update() {
    yum check-update rspamd &>/dev/null
    if [ "$?" = 0 ]; then
        $DIALOG --backtitle "$TITLE_MAIN" --title "Update rspamd" --clear --msgbox 'No Rspamd update available.' 0 0
    else
        clear
        service rspamd stop
        yum update -y rspamd
        [ "$?" = 0 ] && printf "%s" $RSPAMD_SCRIPT | base64 -d | gunzip > /etc/init.d/rspamd
        service rspamd start
    fi
}
# select rspamd feature in dialog checklist
# parameters:
# none
# return values:
# none
dialog_feature_rspamd() {
    DIALOG_CLUSTER='Enable master-slave cluster'
    DIALOG_SENDER='Enable sender-whitelist cron'
    DIALOG_GREYLIST='Disable greylisting'
    DIALOG_REJECT='Disable rejecting'
    DIALOG_BAYES='Enable Bayes-learning'
    DIALOG_HEADERS='Enable detailed headers'
    DIALOG_HISTORY='Enable detailed history'
    DIALOG_REPUTATION='Enable URL reputation'
    DIALOG_SPAMASSASSIN='Enable Heinlein SA rules'
    DIALOG_PHISHING='Enable phishing detection'
    DIALOG_PYZOR='Enable Pyzor'
    DIALOG_RAZOR='Enable Razor'
    DIALOG_UPDATE='Enable automatic Rspamd updates'
    DIALOG_RULESUPDATE='Enable automatic SA rules updates'
    DIALOG_ELASTIC='Enable Elasticsearch logging'
    for FEATURE in cluster sender greylist reject bayes headers history reputation spamassassin phishing pyzor razor update rulesupdate elastic; do
        declare STATUS_${FEATURE^^}="$(check_enabled_$FEATURE)"
    done
    [ "$STATUS_ELASTIC" = 'on' ] && ELASTIC_HOST="$(awk 'match($0, /server = "([^:]+):9200";/, a) {print a[1]}' "$CONFIG_ELASTIC")" || ELASTIC_HOST=''
    NUM_PEERS="$(grep '<Peer address="' /var/cs-gateway/peers.xml | wc -l)"
    ARRAY_RSPAMD=()
    [ "$NUM_PEERS" -gt 1 ] && ARRAY_RSPAMD+=("$DIALOG_CLUSTER" '' "$STATUS_CLUSTER")
    ARRAY_RSPAMD+=("$DIALOG_SENDER" '' "$STATUS_SENDER")
    ARRAY_RSPAMD+=("$DIALOG_GREYLIST" '' "$STATUS_GREYLIST")
    ARRAY_RSPAMD+=("$DIALOG_REJECT" '' "$STATUS_REJECT")
    ARRAY_RSPAMD+=("$DIALOG_BAYES" '' "$STATUS_BAYES")
    ARRAY_RSPAMD+=("$DIALOG_HEADERS" '' "$STATUS_HEADERS")
    ARRAY_RSPAMD+=("$DIALOG_HISTORY" '' "$STATUS_HISTORY")
    ARRAY_RSPAMD+=("$DIALOG_SPAMASSASSIN" '' "$STATUS_SPAMASSASSIN")
    ARRAY_RSPAMD+=("$DIALOG_REPUTATION" '' "$STATUS_REPUTATION")
    ARRAY_RSPAMD+=("$DIALOG_PHISHING" '' "$STATUS_PHISHING")
    check_installed_pyzorrazor && ARRAY_RSPAMD+=("$DIALOG_PYZOR" '' "$STATUS_PYZOR")
    check_installed_pyzorrazor && ARRAY_RSPAMD+=("$DIALOG_RAZOR" '' "$STATUS_RAZOR")
    ARRAY_RSPAMD+=("$DIALOG_UPDATE" '' "$STATUS_UPDATE")
    ARRAY_RSPAMD+=("$DIALOG_RULESUPDATE" '' "$STATUS_RULESUPDATE")
    ARRAY_RSPAMD+=("$DIALOG_ELASTIC" '' "$STATUS_ELASTIC")
    exec 3>&1
    DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Apply' --checklist 'Choose rspamd features to enable' 0 0 0 "${ARRAY_RSPAMD[@]}" 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        LIST_ENABLED=''
        RSPAMD_RESTART=''
        if [ "$NUM_PEERS" -gt 1 ]; then
            if echo "$DIALOG_RET" | grep -q "$DIALOG_CLUSTER"; then
                if [ "$STATUS_CLUSTER" = 'off' ]; then
                    enable_cluster
                    RSPAMD_RESTART=1
                fi
                LIST_ENABLED+=$'\n''Master-slave cluster'
            else
                if [ "$STATUS_CLUSTER" = 'on' ]; then
                    disable_cluster
                    RSPAMD_RESTART=1
                fi
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_SENDER"; then
            [ "$STATUS_SENDER" = 'off' ] && enable_sender
            LIST_ENABLED+=$'\n''Sender-whitelist cron'
        else
            [ "$STATUS_SENDER" = 'on' ] && disable_sender
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_GREYLIST"; then
            if [ "$STATUS_GREYLIST" = 'off' ]; then
                enable_greylist
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Disable greylisting'
        else
            if [ "$STATUS_GREYLIST" = 'on' ]; then
                disable_greylist
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_REJECT"; then
            if [ "$STATUS_REJECT" = 'off' ]; then
                enable_reject
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Disable rejecting'
        else
            if [ "$STATUS_REJECT" = 'on' ]; then
                disable_reject
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_BAYES"; then
            if [ "$STATUS_BAYES" = 'off' ]; then
                enable_bayes
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Bayes-learning'
        else
            if [ "$STATUS_BAYES" = 'on' ]; then
                disable_bayes
                RSPAMD_RESTART=1
            fi    
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_HEADERS"; then
            if [ "$STATUS_HEADERS" = 'off' ]; then
                enable_headers
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Detailed headers'
        else
            if [ "$STATUS_HEADERS" = 'on' ]; then
                disable_headers
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_HISTORY"; then
            if [ "$STATUS_HISTORY" = 'off' ]; then
                enable_history
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Detailed history'
        else
            if [ "$STATUS_HISTORY" = 'on' ]; then
                disable_history
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_SPAMASSASSIN"; then
            if [ "$STATUS_SPAMASSASSIN" = 'off' ]; then
                enable_spamassassin
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Heinlein SA rules'
        else
            if [ "$STATUS_SPAMASSASSIN" = 'on' ]; then
                disable_spamassassin
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_REPUTATION"; then
            if [ "$STATUS_REPUTATION" = 'off' ]; then
                enable_reputation
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''URL reputation'
        else
            if [ "$STATUS_REPUTATION" = 'on' ]; then
                disable_reputation
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_PHISHING"; then
            if [ "$STATUS_PHISHING" = 'off' ]; then
                enable_phishing
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Phishing detection'
        else
            if [ "$STATUS_PHISHING" = 'on' ]; then
                disable_phishing
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_PYZOR"; then
            if [ "$STATUS_PYZOR" = 'off' ]; then
                enable_pyzor
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Pyzor'
        else
            if [ "$STATUS_PYZOR" = 'on' ]; then
                disable_pyzor
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_RAZOR"; then
            if [ "$STATUS_RAZOR" = 'off' ]; then
                enable_razor
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Razor'
        else
            if [ "$STATUS_RAZOR" = 'on' ]; then
                disable_razor
                RSPAMD_RESTART=1
            fi
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_UPDATE"; then
            [ "$STATUS_UPDATE" = 'off' ] && enable_update
            LIST_ENABLED+=$'\n''Automatic Rspamd updates'
        else
            [ "$STATUS_UPDATE" = 'on' ] && disable_update
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_RULESUPDATE"; then
            [ "$STATUS_RULESUPDATE" = 'off' ] && enable_rulesupdate
            LIST_ENABLED+=$'\n''Automatic SA rules updates'
        else
            [ "$STATUS_RULESUPDATE" = 'on' ] && disable_rulesupdate
        fi
        if echo "$DIALOG_RET" | grep -q "$DIALOG_ELASTIC"; then
            if [ "$STATUS_ELASTIC" = 'off' ]; then
                enable_elastic "$ELASTIC_HOST"
                RSPAMD_RESTART=1
            fi
            LIST_ENABLED+=$'\n''Elasticsearch logging'
        else
            if [ "$STATUS_ELASTIC" = 'on' ]; then
                disable_elastic "$ELASTIC_HOST"
                RSPAMD_RESTART=1
            fi
        fi
        [ "$RSPAMD_RESTART" = 1 ] && service rspamd restart &>/dev/null
        [ -z "$LIST_ENABLED" ] && LIST_ENABLED+=$'\n''None'
        $DIALOG --backtitle "$TITLE_MAIN" --title 'Enabled features' --clear --msgbox "$LIST_ENABLED" 0 0
    fi
}
# select Rspamd configuration to manage in dialog menu
# parameters:
# none
# return values:
# none
dialog_config_rspamd() {
    DIALOG_IP='Whitelist sender IP'
    DIALOG_DOMAIN='Whitelist sender domain'
    DIALOG_FROM='Whitelist sender from'
    DIALOG_PYZORRAZOR='Install Pyzor & Razor plugins'
    DIALOG_BAYES='Reset Bayes spam database'
    DIALOG_WEBUI='Rspamd web UI access'
    DIALOG_STATS='Rspamd info & stats'
    DIALOG_UPDATE='Update Rspamd'
    DIALOG_SENDER='Generate sender domain/from whitelists'
    DIALOG_SERVICE='Fix Rspamd service script'
    while true; do
        DIALOG_PYZORRAZOR_INSTALLED="$DIALOG_PYZORRAZOR"
        check_installed_pyzorrazor && DIALOG_PYZORRAZOR_INSTALLED+=' (installed)'
        ARRAY_RSPAMD=()
        ARRAY_RSPAMD+=("$DIALOG_IP" '')
        ARRAY_RSPAMD+=("$DIALOG_DOMAIN" '')
        ARRAY_RSPAMD+=("$DIALOG_FROM" '')
        ARRAY_RSPAMD+=("$DIALOG_PYZORRAZOR_INSTALLED" '')
        ARRAY_RSPAMD+=("$DIALOG_BAYES" '')
        ARRAY_RSPAMD+=("$DIALOG_WEBUI" '')
        ARRAY_RSPAMD+=("$DIALOG_STATS" '')
        ARRAY_RSPAMD+=("$DIALOG_UPDATE" '')
        ARRAY_RSPAMD+=("$DIALOG_SENDER" '')
        [ "$(md5sum /etc/init.d/rspamd | awk '{print $1}')" = "$MD5_RSPAMD" ] || ARRAY_RSPAMD+=("$DIALOG_SERVICE" '')
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN"                                    \
            --cancel-label 'Back' --ok-label 'Edit' --menu 'Manage Clearswift configuration' 0 0 0 \
            "${ARRAY_RSPAMD[@]}" 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_IP")
                    "$TXT_EDITOR" "$WHITELIST_IP";;
                "$DIALOG_DOMAIN")
                    "$TXT_EDITOR" "$WHITELIST_DOMAIN";;
                "$DIALOG_FROM")
                    "$TXT_EDITOR" "$WHITELIST_FROM";;
                "$DIALOG_PYZORRAZOR_INSTALLED")
                    install_pyzorrazor;;
                "$DIALOG_BAYES")
                    reset_bayes;;
                "$DIALOG_WEBUI")
                    webui_access;;
                "$DIALOG_STATS")
                    LIST_STATS="Rspamd version: $(rspamd -v | awk '{print $4}')"$'\n\n''Rspamd stats:'$'\n\n'"$(rspamc stat | grep 'Messages scanned:\|Messages with action add header:\|Messages with action no action:\|Messages learned:\|Connections count:')"
                    $DIALOG --backtitle "$TITLE_MAIN" --title 'Rspamd info & stats' --clear --msgbox "$LIST_STATS" 0 0;;
                "$DIALOG_UPDATE")
                    rspamd_update;;
                "$DIALOG_SENDER")
                    FILE_SCRIPT='/tmp/sender_whitelist.sh'
                    printf "%s" $SENDER_SCRIPT | base64 -d | gunzip > $FILE_SCRIPT
                    chmod 700 $FILE_SCRIPT
                    $FILE_SCRIPT
                    rm -f $FILE_SCRIPT;;
                "$DIALOG_SERVICE")
                    printf "%s" $RSPAMD_SCRIPT | base64 -d | gunzip > /etc/init.d/rspamd;;
            esac
        else
            break
        fi
    done
}
# manage monthly email stats reports in dialog menu
# parameters:
# none
# return values:
# none
dialog_report() {
    DIALOG_STATUS="Current status: "
    DIALOG_EMAIL="Add/remove email recipients"
    DIALOG_SCRIPT="Edit script"
    while true; do
        [ -f $SCRIPT_STATS ] && [ -f $CRON_STATS ] && STATUS_CRON="enabled" || STATUS_CRON="disabled"
        ARRAY_MAIL=()
        ARRAY_MAIL+=("$DIALOG_STATUS$STATUS_CRON" "")
        if [ "$STATUS_CRON" = "enabled" ]; then
            ARRAY_MAIL+=("$DIALOG_EMAIL" "")
            ARRAY_MAIL+=("$DIALOG_SCRIPT" "")
        fi
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "Other configurations"                        \
            --cancel-label "Back" --ok-label "Edit" --menu "Monthly email stats reports" 0 40 0 \
            "${ARRAY_MAIL[@]}" 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_STATUS$STATUS_CRON")
                    if [ "$STATUS_CRON" = "enabled" ]; then
                        rm -f $SCRIPT_STATS $CRON_STATS
                    else
                        PACKED_SCRIPT="
                        H4sIAFgu9VsAA71Xe3PiNhD/n0+xVTwHHDXG3Fxyl5xvQnOkk5mEpEA67UCaUbAAtUbmLEGSC/Sz
                        dyU/sAlzz5k6D6zVand/+9Ky95Nzx4VzR+W0tAcnAaORvOdjBb32rxCEE6CCBo+fWIS71/cMeuFs
                        xiKoSPN5LJgahcLGP7kIFBeT+iicVZHXbTjNhvumtIfvKGbMAyZhHEYQUKngVQN8+ihLyY5HnCWN
                        HFw5I2lPqGL39NGZUR7UX9aRSkoXravbfrfV6V1ddvvIjmqdeSjVmD/Y4ULdhQvhOyqiQs7DSNVn
                        dE5Q8YQp4EKxCDGAFgcRC+gj7sxpRGcMd+QhrkQoGH5ETC0iAUsaLJih7zqLMm9TeqUKTyXAp9Xt
                        tv70KlWzOD/r9W+77XOkEKsyidgcynKm5ofDQf3l8KYMVgENrIDe/wPlp3mEcsFqrssJyT6F8mA4
                        xN8bPJVnqBKjSfuz07pox9rQXLA2yo/ADw2Xfk4urzv9dtdrZJRTpHzwCMkIWtjJ5fl5+6Tf/qBl
                        EevJ4Boc36xJQZp++BgGyLJRT8DDdYWNpiFYG0Fb6FxtPNwcgZoyURCY+XFgJdbeeHn5gLIf5hF8
                        UYX2D9TArZJn8mPQboE+5oVl6imSqksIWxJ9nTLpYgD2J8RupCM4ePEiRlLzKgUELokzJDt8cYnR
                        Ou22f7tud/ppML4hECYIRndBkrZhtTLx+RpnEbAnasNbELWbf1f8trBsVOZSjBfhG33PbH+eMaU1
                        FuNVxJfYGeDsCrpUTJgsXbX6GJiOVx4O3MawXt6Otu5CdfPjvEmZa155hexvm8O6u/8mdwiZ3zY1
                        zfC7+yUdBm5qqiLZR3D34ZVbBe3+7MCBPhDzNw2gTAnRSg5QicWHdVIyiM90GnVa57nekOslmFtJ
                        KIt8SSxzktM4FfnQbZL52GmcYd0ZDvHfRLeJX1q9dtam9uBMmFYJVMrFDDvyfONUnwV8yaJHfJHY
                        yaniochFKTl5CGlLM+1w6GE7S7o4rJjZIVZiLIbyfgR2kJTNHrSCIC9dYhJRBTRi2IF1p45tmy3w
                        hrhjkPb1nBGXCemzVkDSchVVC+lJJhQ2VEOzl0Dc5oHJCZek9mpqavJKN2r7nqrR9Jn1+jahgb4H
                        /mYjhb4OuMAs3FjXTTY21sHr1w3I25ZKXJdMdt9qI2UWn1iMriV93/T0XuG+JDku73PPhtG86CSA
                        1SgMFjMBtipuxuLwCrT75700CBkE4nOJt7tAYDCOwhnJgYkZEEKkVCC9xpbHvud8ofIP9E0o8T6H
                        1ULwj2CPkqUtIlhNGfU/hyTczpXteWHbErThdoE15DVymZEmxg5oPyhvG+oqufKJR7aGgXRjQApd
                        EQv+W33TD+fYE7NKi9iIzzkWiDzM4frqmoLn9R6DgsTIfTARjNuSCr13DjYlWKkIbB/I8P3P5Dvi
                        m2DIvP6DIL6rMfx/MNFKX0+peWjbiVd+VlO60rx3maF4lVW45x7xd17n9IjXatUnnBwqFod/wYl5
                        HexBCRy+XufwJNs7EOl95y/L8b9YpevSZlBxi9NDDPZa0gnThYrfQ5jAyRysRhWYHrvtLL5JU3vg
                        CtwSjhIbmZVAblzQfO/4bOmIRRBUd+kSofleE38joUtUQe8ClhPe1MIv/rjttbu/4yBoVXw+gZqc
                        akw1EfpCSjaC2UM6iWpM6cBOjsnWIJpUqXEGKN3XbXfXUJWDk+neZf6ICn1Zjrm+KbU4ySK8tnP2
                        v9L2564X1GYYbYktxKpMMXu0i6s3cBEKNQ0eY0dDzIz5g/biSNgDnfJezpzD5muk6wk8k3G8ecfU
                        qBpflP4DGPryLFQOAAA=
                        "
                        printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > $SCRIPT_STATS
                        chmod +x $SCRIPT_STATS
                        echo "$SCRIPT_STATS $EMAIL_DEFAULT" >> $CRON_STATS
                    fi;;
                "$DIALOG_EMAIL")
                    monthly_report;;
                "$DIALOG_SCRIPT")
                    $TXT_EDITOR $SCRIPT_STATS;;
            esac
        else
            break
        fi
    done
}
# manage monthly sender anomaly detection in dialog menu
# parameters:
# none
# return values:
# none
dialog_anomaly() {
    DIALOG_STATUS="Current status: "
    DIALOG_EMAIL="Add/remove email recipients"
    DIALOG_SCRIPT="Edit script"
    while true; do
        [ -f $SCRIPT_ANOMALY ] && [ -f $CRON_ANOMALY ] && STATUS_CRON="enabled" || STATUS_CRON="disabled"
        ARRAY_MAILADDR=()
        ARRAY_MAILADDR+=("$DIALOG_STATUS$STATUS_CRON" "")
        if [ "$STATUS_CRON" = "enabled" ]; then
            ARRAY_MAILADDR+=("$DIALOG_EMAIL" "")
            ARRAY_MAILADDR+=("$DIALOG_SCRIPT" "")
        fi
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "Other configurations"                        \
            --cancel-label "Back" --ok-label "Edit" --menu "Sender anomaly detection" 0 40 0    \
            "${ARRAY_MAILADDR[@]}" 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_STATUS$STATUS_CRON")
                    if [ "$STATUS_CRON" = "enabled" ]; then
                        rm -f $SCRIPT_ANOMALY $CRON_ANOMALY
                    else
                        PACKED_SCRIPT="
                        H4sIAIplbVwAA7VX/3OaSBT/nb/idUOK1ACaTmfuTMzUJtp6E00nml47MXEQVqGFxcJak2u8v/3e
                        AspqTNprJ8w4Luz7+nnvfRZ2nlkjn1kjO/GUHXA86nwZ2iwK7eDWTDz4UDWrZkXZwb3jaHob+xOP
                        Q8nRYb9S/QO6lB9HDC4YpzGjXkhZMqKxzWdsAm/D0TvU8jifJjXLms/nJqPciZiBv2QWcJ9NTCcK
                        U9uNGfeiOKnh8mJOoReFIY2hNDOTdPV6q6aO0iexCR07duDEp/GXhDIohaabrx9SU07P3g5b7dNm
                        nVjf7NgKoonlJMbE5nRu31qh7QemWnLxFspk95OxGxq7LtFNlCNKp/Fx2Gm0T3v1V5UK7EBo34DQ
                        SMAOgmhOXZhi6OjdxT+xdO3bVOm8edx+3252+6iZ68XU8ac+ZXxdWZhT+p33uR/N4uHUwvvUjZbu
                        SMZW24U1TTk+67bab4d/v2v3m6ftXh+lEAsrr+xw7vmcBn7CERA21pRuo9Mcnpyhv+7wpNlqXJyi
                        hp+4URCYLtUUfwyXYPwDRK0SuDoA7lGmAF7U8SIgF4k9oTVQS9hGlNkhBbWiAxXxGquoSKZw43Oo
                        KmNf2HwmrI7R6rIg24yzCBB4GPsBBfsbmrRHAZWM7QtjO6BWwSgAFQ/28UFIExGbIuoxtAMa85IO
                        31Plzsdhr3n+oXlex1r7Eygn2IIcyixyWZJQB8IbzCiLAdO+A3v+BYwWeU1A+z6NfcbRxULT4Q4S
                        oWiwGJccAwSjCpn4mmDqtUBy5X896SJxx2Ys4pg4c9OWwKaKv9GYFGIi/ZfpLUIg/qQ61ola8qKE
                        p+UwXD1Ty31Lcugdnj/f0NzSD0QqibpPMME0JiMBcll40q+gkfUYuJRTh/sRI2D0IAn5tC4lXdt/
                        hc9jkKLUX6/HJVBXFkq/jc96/UbnvUgpm8rdFuaT985qUPJMEpwiwwdiXauFKlhEe+ZqUEjL6sU0
                        /bSNQkUR84VZdU+wlQhRcLawU2Nqu9Duts7ynQNwoxTBXDDvLFUSeaxnVpOyOdgi4Ls73J/EdArG
                        VyDXamZOJXBPeqPPuhednGN+IpzqMpxlFsPGafO8L1JePs2ae7MoG07Fhbidfxq+abbOzpuiqmnw
                        5PqyYvxpXA3KkKcARCqYTtZMFIMkG9vuTupcqZxLJ+oKBgJHR3KLbNqQsq6ubdIgofekhdkixQxf
                        OdZNgF8iwOSelTRPoX8zjaVQkdvUwoGOszRBE6vD6UEYxLXs7gTbWw7IehwdizyGzaP4iCunqC23
                        99D73VptjUNymDdOIZZPkTTJ5bqqDZhGtjheEq4bMQqHcJh1rzZFGhv7N0Y046NoxgRRLI81rHTW
                        4eM4CuuHZFX5cRSX/Hr1wD+sd1sHfrmsf8d6l1Qf/gUrE7bwvMobxF8sFpo4brB+WrLctybiGY+R
                        5IEMjvbIUgKra7na8ni6gxnzv4LhrJ9XIg4ywMPzSO6e3ONArSyIruRwSejkeBWnavZmQHrpa08C
                        c597EEYxxSa0mWw5fYepkRxc2eSv8ShZHdGS0BJgowUantbrlEqellN7F2/+ah73fxzYJSFXW0Pb
                        6OAH+XXt1PoNklXzkFWyebQ9HeXmLoshls7TTTMPssovUsjP+n4CFhmQpfcB+RGP+CylEcsJqM1m
                        U/PF3I4ZfsPUwMOZEN8Ys9FnfMOqrRNNSiyhzR2vpFb2wHpIC0rmCx0Eh4C1B7YOkg5k1FK6vIar
                        F/qREBitaIhg6PZl9Ur8741wsfi/HFPg/SREI5kvPom2U85/TH9ebf4OAAA=
                        "
                        printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > $SCRIPT_ANOMALY
                        chmod +x $SCRIPT_ANOMALY
                        echo "30 1,7,13,19 * * * root $SCRIPT_ANOMALY $EMAIL_DEFAULT" >> $CRON_ANOMALY
                    fi;;
                "$DIALOG_EMAIL")
                    anomaly_detect;;
                "$DIALOG_SCRIPT")
                    $TXT_EDITOR $SCRIPT_ANOMALY;;
            esac
        else
            break
        fi
    done
}
# toggle DNS query logging
# parameters:
# none
# return values:
# none
toggle_logging() {
    if [ -f "$CONFIG_BIND" ] && grep -q '^logging {$' "$CONFIG_BIND"; then
        STATUS_CURRENT='enabled'
        STATUS_TOGGLE='Disable'
    else
        STATUS_CURRENT='disabled'
        STATUS_TOGGLE='Enable'
    fi
    $DIALOG --backtitle 'Clearswift Configuration' --title 'Toggle DNS query logging' --yesno "DNS query logging is currently $STATUS_CURRENT. $STATUS_TOGGLE?" 0 60
    if [ "$?" = 0 ]; then
        if [ $STATUS_CURRENT = 'disabled' ]; then
            DIR_LOG='/var/log/named'
            mkdir -p "$DIR_LOG"
            chown named:named "$DIR_LOG"
            PACKED_SCRIPT='
            H4sIAEg90FwAA02O0QrCMAxFn+dXhL1r57MfI2W71kCbalMHnfjvZlNBSEg4uZebmENgCfTcdePV
            iyDS/YHC0POFI1bebUvvZl9czMGJT5jcV3Uw0tOMopxF6TiQ8gKbQzqZVWEnro2mZjYeV3YrLHVf
            OYEa1MjLevQVIZf2S9+C/z/56KzeT8agabIAAAA=
            '
            printf "%s" $PACKED_SCRIPT | base64 -d | gunzip >> "$CONFIG_BIND"
        else
            sed -i '/^logging {$/,/^};$/d' "$CONFIG_BIND"
        fi
        service named restart &>/dev/null
    fi
}
# select other configuration to manage in dialog menu
# parameters:
# none
# return values:
# none
dialog_other() {
    DIALOG_AUTO_UPDATE='Auto-update'
    DIALOG_MAIL_INTERN='Mail.intern RoundRobin'
    DIALOG_CONFIG_FW='Firewall settings'
    DIALOG_RECENT_UPDATES='Recently updated packages'
    DIALOG_FORWARDING='Internal DNS forwarding'
    DIALOG_REPORT='Monthly email stats reports'
    DIALOG_ANOMALY='Sender anomaly detection'
    DIALOG_LOG='DNS query logging'
    ARRAY_OTHER=()
    ARRAY_OTHER+=("$DIALOG_AUTO_UPDATE" '')
    ARRAY_OTHER+=("$DIALOG_MAIL_INTERN" '')
    ARRAY_OTHER+=("$DIALOG_CONFIG_FW" '')
    ARRAY_OTHER+=("$DIALOG_RECENT_UPDATES" '')
    ARRAY_OTHER+=("$DIALOG_FORWARDING" '')
    ARRAY_OTHER+=("$DIALOG_REPORT" '')
    ARRAY_OTHER+=("$DIALOG_ANOMALY" '')
    ARRAY_OTHER+=("$DIALOG_LOG" '')
    while true; do
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN"                                  \
            --cancel-label "Back" --ok-label "Edit" --menu "Manage other configuration" 0 40 0   \
            "${ARRAY_OTHER[@]}" 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_AUTO_UPDATE")
                    [ -f $CONFIG_AUTO_UPDATE ] && $TXT_EDITOR $CONFIG_AUTO_UPDATE
                    [ -f $CONFIG_AUTO_UPDATE_ALT ] && $TXT_EDITOR $CONFIG_AUTO_UPDATE_ALT;;
                "$DIALOG_MAIL_INTERN")
                    mail_intern;;
                "$DIALOG_CONFIG_FW")
                    $TXT_EDITOR $CONFIG_FW;;
                "$DIALOG_RECENT_UPDATES")
                    $DIALOG --backtitle "Other configurations" --title "Recently updated packages" --clear --msgbox "$(tail -20 /var/log/yum.log)" 0 0;;
                "$DIALOG_FORWARDING")
                    internal_forwarding;;
                "$DIALOG_REPORT")
                    dialog_report;;
                "$DIALOG_ANOMALY")
                    dialog_anomaly;;
                "$DIALOG_LOG")
                    toggle_logging;;
            esac
        else
            break
        fi
    done
}
# show non-default Postfix options in dialog msgbox
# parameters:
# none
# return values:
# none
show_non_default() {
    PF_INFO="main.cf inbound:"
    PF_PART1="$(grep -v '^#' $PF_IN)"
    [ -z "$PF_PART1" ] || PF_INFO="$PF_INFO"$'\n\n'"$PF_PART1"
    PF_INFO="$PF_INFO"$'\n\n\n'"main.cf outbound:"
    PF_PART1="$(grep -v '^#' $PF_OUT)"
    [ -z "$PF_PART1" ] || PF_INFO="$PF_INFO"$'\n\n'"$PF_PART1"
    $DIALOG --backtitle "$TITLE_MAIN" --title "Active Postfix configuration" --clear --msgbox "$PF_INFO" 0 0
}
# show inbound TLS stats in dialog msgbox
# parameters:
# none
# return values:
# none
show_tls_in() {
    LOG_TODAY="$LOG_FILES$(date +"%Y-%m-%d").log"
    STATS_INFO="non-TLS: $(grep "disconnect from" $LOG_TODAY | grep "starttls=0" | wc -l)"
    STATS_INFO="$STATS_INFO"$'\n\n'"Top 10:"$'\n'
    STATS_INFO="$STATS_INFO$(grep "disconnect from" $LOG_TODAY | grep "starttls=0" | awk '{print $7}' | sort | uniq -c | sort -nr | head)"
    $DIALOG --backtitle "$TITLE_MAIN" --title "TLS inbound statistics" --clear --msgbox "$STATS_INFO" 0 0
}
# get internal mail relay
# parameters:
# none
# return values:
# internal mail relay
get_internal() {
    ARRAY_INTERNAL=()
    LIST_RELAY="$(grep 'smtp:\[.*\]' $MAP_TRANSPORT | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
    for NAME_RELAY in $LIST_RELAY; do
        COUNTER=0
        FOUND=""
        for COLLECTED in "${ARRAY_INTERNAL[@]}"; do
            if [ "$NAME_RELAY" = "$(echo $COLLECTED | awk '{print $1}')" ]; then
                ARRAY_INTERNAL[$COUNTER]="$NAME_RELAY $(expr $(echo $COLLECTED | awk '{print $2}') + 1)"
                FOUND=1
            fi
            COUNTER="$(expr $COUNTER + 1)"
        done
        [ -z "$FOUND" ] && ARRAY_INTERNAL+=("$NAME_RELAY 1")
    done
    MOST_FREQUENT=""
    for COLLECTED in "${ARRAY_INTERNAL[@]}"; do
        if [ -z "$MOST_FREQUENT" ] || [ "$(echo $COLLECTED | awk '{print $2}')" -gt "$(echo $MOST_FREQUENT | awk '{print $2}')" ]; then
            MOST_FREQUENT="$COLLECTED"
        fi
    done
    echo "$MOST_FREQUENT" | awk '{print $1}'
}
# get search pattern for internal IP addresses
# parameters:
# none
# return values:
# search pattern for internal IP addresses
internal_pattern() {
    IP_PATTERN='\[10\.'             #  10.0.0.0/8
    IP_PATTERN+='|\[192\.168\.'     # 192.168.0.0/16
    for i in $(seq 16 31); do       # 172.16.0.0/12
        IP_PATTERN+="|\[172\.$i\."
    done
    INTERNAL_RELAY="$(get_internal)"
    [ -z "$INTERNAL_RELAY" ] || IP_PATTERN+="|$(echo $INTERNAL_RELAY | sed 's/\./\\\./g')"
    echo "$IP_PATTERN"
}
# show outbound TLS stats in dialog msgbox
# parameters:
# none
# return values:
# none
show_tls_out() {
    LOG_TODAY="$LOG_FILES$(date +"%Y-%m-%d").log"
    IP_PATTERN="$(internal_pattern)"
    STATS_INFO="non-TLS: $(grep postfix-outbound "$LOG_TODAY" | grep tls_used=0 | egrep -v $IP_PATTERN | wc -l)"
    STATS_INFO="$STATS_INFO"$'\n\n'"Top 10:"$'\n'
    STATS_INFO="$STATS_INFO$(grep postfix-outbound "$LOG_TODAY" | grep tls_used=0 | egrep -v $IP_PATTERN | awk '{print $7}'| awk -F "=" '{print $2}' | awk -F "[" '{print $1}'| sort | uniq -c | sort -nr | head)"
    $DIALOG --backtitle "$TITLE_MAIN" --title "TLS inbound statistics" --clear --msgbox "$STATS_INFO" 0 0
}
# show general stats in dialog msgbox
# parameters:
# none
# return values:
# none
show_general() {
    LOG_TODAY="$LOG_FILES$(date +"%Y-%m-%d").log"
    IP_PATTERN="$(internal_pattern)"
    STATS_INFO="Total inbound:  $(grep 'relay\=' "$LOG_TODAY" | egrep "$IP_PATTERN" | wc -l)"
    STATS_INFO="$STATS_INFO"$'\n\n'"Total outbound: $(grep 'relay\=' "$LOG_TODAY" | grep 'status=sent' | grep -v "127.0.0.1" | egrep -v "$IP_PATTERN|smtp-watch" | wc -l)"
    STATS_INFO="$STATS_INFO"$'\n\n'"Total rejected: $(grep ' 550 ' "$LOG_TODAY" | wc -l)"
    STATS_INFO="$STATS_INFO"$'\n\n'"Top 10 inbound recipients:"$'\n'"$(grep 'relay\=' "$LOG_TODAY" | grep 'status=sent' | egrep "$IP_PATTERN" | awk '{print $6}' | sed 's/to=<//g' | tr -d "\>," | sort | uniq -c | sort -nr | head)"
    STATS_INFO="$STATS_INFO"$'\n\n'"Top 10 outbound recipients:"$'\n'"$(grep 'relay\=' "$LOG_TODAY" | grep 'status=sent' | grep -v "127.0.0.1" | egrep -v "$IP_PATTERN|smtp-watch" | awk '{print $6}' | sed 's/to=<//g' | tr -d "\>," | sort | uniq -c | sort -nr | head)"
    STATS_INFO="$STATS_INFO"$'\n\n'"Top 10 senders:"$'\n'"$(grep 'postfix-outbound' "$LOG_TODAY" | grep "from=<" | awk '{for(i=1;i<=NF;i++){if ($i ~ /from=</) {print $i}}}' | sed 's/from=<//g' | tr -d "\>," | sed '/^$/d' | sort | uniq -c | sort -nr | head)"
    $DIALOG --backtitle "$TITLE_MAIN" --title "General statistics" --clear --msgbox "$STATS_INFO" 0 0
}
# ask user for search term, search Postfix mail logs for it and show results in editor
# parameters:
# none
# return values:
# none
search_log() {
    exec 3>&1
    DIALOG_RET="$(dialog --clear --backtitle "Postfix infos & stats"            \
        --title "Postfix daily log search"                                      \
        --inputbox "Enter search term to lookup in daily Postfix log" 0 55 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        $DIALOG --backtitle "Postfix infos & stats" --title "Postfix daily mail log" --clear --msgbox "$(grep "$DIALOG_RET" "$LOG_FILES$(date +"%Y-%m-%d").log" | tail -30)" 0 0
    fi
}
# select configuration to show in dialog menu
# parameters:
# none
# return values:
# none
dialog_show() {
    DIALOG_NEW_SETTINGS="Custom Postfix settings"
    DIALOG_GENERAL="General daily stats"
    DIALOG_TLS_IN="TLS inbound daily stats"
    DIALOG_TLS_OUT="TLS outbound daily stats"
    DIALOG_LOG="Search Postfix daily mail log"
    while true; do
        exec 3>&1
        DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN"                                       \
            --cancel-label "Back" --ok-label "Edit" --menu "Postfix infos & stats" 0 40 0             \
            "$DIALOG_NEW_SETTINGS" ""                                                                 \
            "$DIALOG_GENERAL" ""                                                                      \
            "$DIALOG_TLS_IN" ""                                                                       \
            "$DIALOG_TLS_OUT" ""                                                                      \
            "$DIALOG_LOG" ""                                                                          \
            2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_NEW_SETTINGS")
                    show_non_default;;
                "$DIALOG_GENERAL")
                    show_general;;
                "$DIALOG_TLS_IN")
                    show_tls_in;;
                "$DIALOG_TLS_OUT")
                    show_tls_out;;
                "$DIALOG_LOG")
                    search_log;;
            esac
        else
            break
        fi
    done
}
# perform login to CS GUI
# parameters:
# none
# return values:
# none
cs_login() {
    DOMAIN="https://$(hostname -I | sed 's/ //')"
    SESSION_ID=''
    if [ -f $FILE_PASSWORD ]; then
        OUTPUT_CURL="$(curl -k -i -d "pass=$(cat $FILE_PASSWORD)&submitted=true&userid=admin" -X POST "$DOMAIN/Appliance/index.jsp" --silent)"
        if echo "$OUTPUT_CURL" | grep -q 'Sorry, the account you are attempting to access is locked due to unsuccessful login attempts.' ||         \
            echo "$OUTPUT_CURL" | grep -q 'Sorry, the user name or password you supplied is invalid or you do not have permission to log in.'; then
            rm -f $FILE_PASSWORD
        else
            SESSION_ID="$(echo "$OUTPUT_CURL" | grep 'Set-Cookie: JSESSIONID=' | awk '{print $2}')"
        fi
    fi
    if [ -z "$SESSION_ID" ]; then
        exec 3>&1
        DIALOG_RET="$(dialog --clear --backtitle "$TITLE_MAIN" --title "Clearswift GUI login" --passwordbox "Enter CS admin password" 0 50 2>&1 1>&3)"
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
            OUTPUT_CURL="$(curl -k -i -d "pass=$DIALOG_RET&submitted=true&userid=admin" -X POST "$DOMAIN/Appliance/index.jsp" --silent)"
            if echo "$OUTPUT_CURL" | grep -q 'Sorry, the account you are attempting to access is locked due to unsuccessful login attempts.'; then
                $DIALOG --clear --backtitle "$TITLE_MAIN" --msgbox "Too many incorrect login attempts. Account locked. Try again in 10m." 0 0
            elif echo "$OUTPUT_CURL" | grep -q 'Sorry, the user name or password you supplied is invalid or you do not have permission to log in.'; then
                $DIALOG --clear --backtitle "$TITLE_MAIN" --msgbox "Incorrect password." 0 0
            else
                SESSION_ID="$(echo "$OUTPUT_CURL" | grep 'Set-Cookie: JSESSIONID=' | awk '{print $2}')"
                echo "$DIALOG_RET" > $FILE_PASSWORD
            fi
        fi
    fi
}
# commit selected configuration to CS
# parameters:
# none
# return values:
# none
apply_config() {
    DOMAIN="https://$(hostname -I | sed 's/ //')"
    cs_login
    if [ -f "$FILE_PASSWORD" ]; then
        SESSION_ID="$(curl -k -i -d "pass=$(cat $FILE_PASSWORD)&submitted=true&userid=admin" -X POST "$DOMAIN/Appliance/index.jsp" --silent | grep 'Set-Cookie: JSESSIONID=' | awk '{print $2}')"
        if [ ! -z "$SESSION_ID" ]; then
            curl -k -i -d "policy=true&system=true&pmm=true&proxy=true&peers=true&users=true&reports=true&tlsCertificates=true&maintenance=true&detail='applied by $TITLE_MAIN'&reason=764c31c0-8d6a-4bf2-ab22-44d61b6784fb&planned=yes&items=" \
        	    --header "Cookie: $SESSION_ID" -X POST "$DOMAIN/Appliance/Deployer/StartDeployment.jsp" &>/dev/null
            APPLY_NEEDED=''
        fi
    fi
}
###################################################################################################
init_cs() {
    clear
    echo 'Performing base setup... this may take a while on first run'
    # enable CS RHEL repo
    [ -f /etc/yum.repos.d/cs-rhel-mirror.repo ] && sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/cs-rhel-mirror.repo
    # install vim editor
    which vim &>/dev/null || yum install -y vim --enablerepo=cs-* &>/dev/null
    # install dialog
    which dialog &>/dev/null || yum install -y dialog --enablerepo=cs-* &>/dev/null
    # create custom settings dirs
    mkdir -p /opt/cs-gateway/custom/postfix-{inbound,outbound}
    touch $CONFIG_PF
    chmod +x $CONFIG_PF
    chown cs-admin:cs-adm $CONFIG_PF
    grep -q $CONFIG_PF $PF_CUSTOMISE || echo $'\n'"$CONFIG_PF" >> $PF_CUSTOMISE
    head -1 $CONFIG_PF | grep -q '^#!/bin/bash' || echo '#!/bin/bash' >> $CONFIG_PF
    grep -q '*filter' "$CONFIG_FW" || echo '*filter' >> "$CONFIG_FW"
    grep -q ':INPUT DROP \[0:0\]' "$CONFIG_FW" || echo ':INPUT DROP [0:0]' >> "$CONFIG_FW"
    grep -q ':FORWARD DROP \[0:0\]' "$CONFIG_FW" || echo ':FORWARD DROP [0:0]'  >> "$CONFIG_FW"
    grep -q ':OUTPUT DROP \[0:0\]' "$CONFIG_FW" || echo ':OUTPUT DROP [0:0]' >> "$CONFIG_FW"
    chown -R cs-admin:cs-adm /opt/cs-gateway/custom
    # create alias shortcuts for menu and Mail Logs
    grep -q 'alias pflogs' /root/.bashrc || echo 'alias pflogs="tail -f /var/log/cs-gateway/mail.$(date +%Y-%m-%d).log"' >> /root/.bashrc
    grep -q "Return to CS menu with 'exit'" /home/cs-admin/.bash_profile || echo "echo -e $'\n'\"\e[91m===============================\"$'\n'\" Return to CS menu with 'exit'\"$'\n'\"===============================\e[0m\"$'\n'" >> /home/cs-admin/.bash_profile
    # create custom commands directory
    mkdir -p "$DIR_COMMANDS"
    chown cs-admin:cs-adm "$DIR_COMMANDS"
}
# print program information in dialog msgbox
# parameters:
# none
# return values:
# none
print_info() {
    TMP_INFO="/tmp/TMPshowinfo"
    if [ ! -f $TMP_INFO ]; then
        INFO_START=$(expr $(grep -n '###################################################################################################' $0 | head -1 | awk -F: '{print $1}') + 1)
        INFO_END=$(expr $(grep -n '# Changelog:' $0 | head -1 | awk -F: '{print $1}') - 2)
        INFO_TEXT="$(sed -n "$INFO_START,"$INFO_END"p" $0 | sed 's/^#//g' | sed 's/^ //g')"
        $DIALOG --clear --backtitle "$TITLE_MAIN" --title 'Program info' --ok-label 'ESC to not show again / Enter to continue' --msgbox "$INFO_TEXT" 0 0
        [ "$?" != 0 ] && touch $TMP_INFO
    fi
}
# check for update and when available ask user whether to install it and show changelog
# parameters:
# none
# return values:
# none
check_update() {
    TMP_UPDATE='/tmp/TMPupdate'
    wget $LINK_UPDATE -O $TMP_UPDATE &>/dev/null
    VERSION="$(grep '^# menu.sh V' $TMP_UPDATE | awk -FV '{print $2}' | awk '{print $1}')"
    MAJOR_DL="$(echo $VERSION | awk -F. '{print $1}')"
    MINOR_DL="$(echo $VERSION | awk -F. '{print $2}')"
    BUILD_DL="$(echo $VERSION | awk -F. '{print $3}')"
    VERSION="$(grep '^# menu.sh V' $0 | awk -FV '{print $2}' | awk '{print $1}')"
    MAJOR_CURRENT="$(echo $VERSION | awk -F. '{print $1}')"
    MINOR_CURRENT="$(echo $VERSION | awk -F. '{print $2}')"
    BUILD_CURRENT="$(echo $VERSION | awk -F. '{print $3}')"
    if [ "$MAJOR_DL" -gt "$MAJOR_CURRENT" ] ||
       ([ "$MAJOR_DL" = "$MAJOR_CURRENT" ] && [ "$MINOR_DL" -gt "$MINOR_CURRENT" ]) ||
       ([ "$MAJOR_DL" = "$MAJOR_CURRENT" ] && [ "$MINOR_DL" = "$MINOR_CURRENT" ] && [ "$BUILD_DL" -gt "$BUILD_CURRENT" ]); then
        $DIALOG --clear --backtitle "$TITLE_MAIN" --yesno 'New update available. Install?' 0 40
        if [ "$?" = 0 ]; then
            INFO_START=$(expr $(grep -n '# Changelog:' $TMP_UPDATE | head -1 | awk -F: '{print $1}') + 1)
            INFO_END=$(expr $(grep -n '###################################################################################################' $TMP_UPDATE | head -2 | tail -1 | awk -F: '{print $1}') - 2)
            INFO_TEXT="$(sed -n "$INFO_START,"$INFO_END"p" $TMP_UPDATE | sed 's/^#//g' | sed 's/^ //g')"
            $DIALOG --clear --backtitle "$TITLE_MAIN" --title "Changelog" --msgbox "$INFO_TEXT" 0 0
            cp -f $TMP_UPDATE $0
            $0
            exit 0
        fi
    fi
}
###################################################################################################
# Main Dialog
###################################################################################################
# root menu; select option in dialog menu
# parameters:
# none
# return values:
# none
grep -q 'alias menu=/root/menu.sh' /root/.bashrc || echo 'alias menu=/root/menu.sh' >> /root/.bashrc
check_update
check_installed_seg && init_cs
write_examples
print_info
DIALOG_SEG='Install Clearswift SEG'
DIALOG_INSTALL='Install features'
DIALOG_FEATURE_POSTFIX='Postfix features'
DIALOG_POSTFIX='Postfix configs'
DIALOG_CLEARSWIFT='Clearswift configs'
DIALOG_FEATURE_RSPAMD='Rspamd features'
DIALOG_CONFIG_RSPAMD='Rspamd configs'
DIALOG_OTHER='Other configs'
DIALOG_SHOW='Postfix infos & stats'
DIALOG_APPLY='Apply configuration'
while true; do
    ARRAY_MAIN=()
    if check_installed_seg; then
        ARRAY_MAIN+=("$DIALOG_INSTALL" '')
        ARRAY_MAIN+=("$DIALOG_FEATURE_POSTFIX" '')
        ARRAY_MAIN+=("$DIALOG_POSTFIX" '')
        ARRAY_MAIN+=("$DIALOG_CLEARSWIFT" '')
        check_installed_rspamd && ARRAY_MAIN+=("$DIALOG_FEATURE_RSPAMD" '')
        check_installed_rspamd && ARRAY_MAIN+=("$DIALOG_CONFIG_RSPAMD" '')
        ARRAY_MAIN+=("$DIALOG_OTHER" '')
        ARRAY_MAIN+=("$DIALOG_SHOW" '')
        [ $APPLY_NEEDED = 1 ] && ARRAY_MAIN+=("$DIALOG_APPLY" '')
    else
        ARRAY_MAIN+=("$DIALOG_SEG" "")
    fi
    exec 3>&1
    DIALOG_RET="$($DIALOG --clear --title "$TITLE_MAIN $VERSION_MENU" --cancel-label 'Exit' --menu '' 0 0 0 "${ARRAY_MAIN[@]}" 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        case "$DIALOG_RET" in
            "$DIALOG_SEG")
                install_seg;;
            "$DIALOG_INSTALL")
                dialog_install;;
            "$DIALOG_FEATURE_POSTFIX")
                dialog_feature_postfix;;
            "$DIALOG_POSTFIX")
                dialog_postfix;;
            "$DIALOG_CLEARSWIFT")
                dialog_clearswift;;
            "$DIALOG_FEATURE_RSPAMD")
                dialog_feature_rspamd;;
            "$DIALOG_CONFIG_RSPAMD")
                dialog_config_rspamd;;
            "$DIALOG_OTHER")
                dialog_other;;
            "$DIALOG_SHOW")
                dialog_show;;
            "$DIALOG_APPLY")
                apply_config;;
        esac
    else
        break;
    fi
done
clear
###################################################################################################
