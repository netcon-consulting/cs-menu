#!/bin/bash
# menu.sh V1.5.0 for Clearswift SEG >= 4.8
#
# Copyright (c) 2018 NetCon Unternehmensberatung GmbH
# https://www.netcon-consulting.com
#
# Authors:
# Uwe Sommer (u.sommer@netcon-consulting.com)
# Dr. Marc Dierksen (m.dierksen@netcon-consulting.com)
###################################################################################################
# Config tool for missing features on Clearswift Secure E-Mail Gateway
# These settings will ease many advanced configuration tasks and highly improve spam detection.
# everything is in this single dialog file, which should be run as root!
#
# Features (26):
#
# Clearswift (13)
# - Letsencrypt certificates via ACME installation and integration to SEG
# - install latest vmware Tools from vmware Repo
# - custom LDAP schedule for Clearswift SEG
# - easy extraction of address lists from last clearswift policy
# - custom firewall rules for SSH access with CIDR support
# - change Tomcat SSL certificate for web administration
# - SSH Key authentication for cs-admin
# - removed triple authentication for cs-admin when becoming root
# - reconfigure local DNS Resolver without forwarders and DNSSec support
# - editable DNS A record for mail.intern (mutiple IP destinations)
# - apply configuration in bash to get all customisations work
# - aliases for quick log access and menu config (pflogs, menu)
# - sample custom command for "run external command" content rule
#
# Postfix settings (12)
# - Postscreen weighted blacklists and Bot detection for Postfix
# - Postscreen deep protocol inspection (optional)
# - postfix verbose TLS logging
# - Postfix recipient verification via next transport hop
# - DANE support for Postfix (outbound)
# - outbound header rewriting (anonymising)
# - Loadbalancing for Postfix transport rules (multi destination transport)
# - custom individual outbound settings (override general main.cf options)
# - postfix notifications for rejected, bounced or error mails
# - custom Postfix ESMTP settings (disable auth and DSN silently)
# - advanced smtpd recipient restrictions and whitelists
# - smtpd delay reject to identify senders of rejected messages
#
# Addons (1)
# - rspamd installation and milter integration
#
# Todo:
# - report based anomaly detection
# - custom reports (via shell and cron)
# - load (useful) Clearswift base policy
#
# Issues:
# - dnssec seems to be disabled in Postfix compile code
#
# Changelog:
# - added internal DNS forwarding
# - improved accuracy of Postfix stats
# - added multi-recipient check for anomaly detection
# - added Cron job for mqueue cleanup
# - bug fixes
#
###################################################################################################
VERSION_MENU="$(grep '^# menu.sh V' $0 | awk '{print $3}')"
DIALOG="dialog"
TXT_EDITOR="vim"
PF_CUSTOMISE="/opt/cs-gateway/scripts/deployment/postfix_customise"
CONFIG_PF="/opt/cs-gateway/scripts/deployment/netcon-postfix.sh" # linked in postfix_customise
CONFIG_FW="/opt/cs-gateway/custom/custom.rules"
CONFIG_INTERN="/var/named/intern.db"
CONFIG_BIND="/etc/named.conf"
CONFIG_AUTO_UPDATE="/etc/yum/yum-cron.conf"
CONFIG_AUTO_UPDATE_ALT="/etc/sysconfig/yum-cron"
CONFIG_LDAP="/var/cs-gateway/ldap/schedule.properties"
MAP_ALIASES="/etc/aliases"
MAP_TRANSPORT="/etc/postfix-outbound/transport.map"
CUSTOM_DIR="/opt/cs-gateway/custom"
DIR_CERT="/var/lib/acme/live/$(hostname)"
DIR_COMMANDS="/opt/cs-gateway/scripts"
DIR_MAPS="/etc/postfix/maps"
DIR_ADDRESS_LISTS="/home/cs-admin/address-lists"
ESMTP_ACCESS="$DIR_MAPS/esmtp_access"
HELO_ACCESS="$DIR_MAPS/check_helo_access"
RECIPIENT_ACCESS="$DIR_MAPS/check_recipient_access"
SENDER_ACCESS="$DIR_MAPS/check_sender_access"
SENDER_REWRITE="$DIR_MAPS/sender_canonical_maps"
WHITELIST_POSTFIX="$DIR_MAPS/check_client_access_ips"
WHITELIST_POSTSCREEN="$DIR_MAPS/check_postscreen_access_ips"
HEADER_REWRITE="$DIR_MAPS/smtp_header_checks"
WHITELIST_RSPAMD="/etc/rspamd/rspamd.conf.local"
LOG_FILES="/var/log/cs-gateway/mail."
LAST_CONFIG="/var/cs-gateway/deployments/lastAppliedConfiguration.xml"
PASSWORD_KEYSTORE="changeit"
PF_IN="/opt/cs-gateway/custom/postfix-inbound/main.cf"
PF_OUT="/opt/cs-gateway/custom/postfix-outbound/main.cf"
PF_INBOUND="/var/cs-gateway/pending/postfix/postfix-inbound"
PF_OUTBOUND="/var/cs-gateway/pending/postfix/postfix-outbound"
SSH_KEYS="/home/cs-admin/.ssh/authorized_keys"
BLACKLISTS="zen.spamhaus.org*3 b.barracudacentral.org*2 ix.dnsbl.manitu.net*2 bl.spameatingmonkey.net bl.spamcop.net list.dnswl.org=127.0.[0..255].0*-2 list.dnswl.org=127.0.[0..255].1*-3 list.dnswl.org=127.0.[0..255].[2..3]*-4"
TMP_PASSWORD="/tmp/TMPpassword"
EMAIL_DEFAULT="uwe@usommer.de"
LINK_UPDATE="https://www.netcon-consulting.com/menu.sh"
CRON_STATS="/etc/cron.monthly/stats_report.sh"
SCRIPT_STATS="/root/send_report.sh"
CRON_ANOMALY="/etc/cron.d/anomaly_detect.sh"
SCRIPT_ANOMALY="/root/check_anomaly.sh"
CRON_CLEANUP="/etc/cron.daily/cleanup_mqueue.sh"
APPLY_NEEDED=0
###################################################################################################
TITLE_MAIN="NetCon Clearswift Configuration"
###################################################################################################
# get install confirmation for specified feature
# parameters:
# $1 - feature name
# return values:
# error code - 0 for install, 1 for cancel
confirm_install() {
    exec 3>&1
    $DIALOG --backtitle "Install features"  \
        --yesno "Install '$1'?" 0 40        \
        2>&1 1>&3
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
    $DIALOG --backtitle "Install features"  \
        --yesno "'$1' already installed. Reinstall?" 0 60        \
        2>&1 1>&3
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
###################################################################################################
# Install Secion
###################################################################################################
# install EPEL repo
# parameters:
# none
# return values:
# none
install_epel() {
    wget http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
    rpm -ivh epel-release-6-8.noarch.rpm
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
    yum update -y
    yum install -y redis rspamd
    rspamadm configwizard
    chkconfig rspamd on
    chkconfig redis on
    [ -f /etc/init.d/redis ] && /etc/init.d/redis start || service redis start
    [ -f /etc/init.d/rspamd ] && /etc/init.d/rspamd start || service rspamd start
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
    if [ ! -f $CONFIG_FW ] || ! grep -qF "I INPUT 4 -i eth0 -p tcp --dport 80 -j ACCEPT" $CONFIG_FW; then
        echo "-I INPUT 4 -i eth0 -p tcp --dport 80 -j ACCEPT" >> $CONFIG_FW
        iptables -I INPUT 4 -i eth0 -p tcp --dport 80 -j ACCEPT
    fi
    yum-config-manager --add-repo https://copr.fedorainfracloud.org/coprs/hlandau/acmetool/repo/epel-6/hlandau-acmetool-epel-6.repo
    yum install -y acmetool
    echo '"acmetool-quickstart-choose-server": https://acme-v01.api.letsencrypt.org/directory' > $TMP_REPONSE
    echo '"acmetool-quickstart-choose-method": listen' >> $TMP_REPONSE
    acmetool quickstart --response-file $TMP_REPONSE
    acmetool want $(hostname)
    if [ $? = 0 ]; then
        # import cert and key into CS keystore
        mv /var/cs-gateway/keystore /var/cs-gateway/keystore.old
        cd /home/cs-admin
        openssl pkcs12 -export -name tomcat -in "$DIR_CERT/cert" -inkey "$DIR_CERT/privkey" -out keystore.p12 -passout pass:$PASSWORD_KEYSTORE
        keytool -importkeystore -destkeystore /var/cs-gateway/keystore -srckeystore keystore.p12 -srcstoretype pkcs12 -deststorepass $PASSWORD_KEYSTORE -srcstorepass $PASSWORD_KEYSTORE
        keytool -list -keystore /var/cs-gateway/keystore -storepass changeit
        cs-servicecontrol restart tomcat
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
    wget -r --no-parent -nd -A 'vmware-tools-repo-RHEL6-*.el6.x86_64.rpm' https://packages.vmware.com/tools/esx/latest/repos/
    rpm -Uvh vmware-tools-repo-RHEL6-*.el6.x86_64.rpm
    yum install -y vmware-tools-esx-nox
    get_keypress
}
# install local DNS resolver
# parameters:
# none
# return values:
# none
install_local_dns() {
    clear
    grep -qF "dnssec-validation auto;" $CONFIG_BIND || sed -i '/include/a   \ \ dnssec-validation auto;' $CONFIG_BIND
    grep -qF "#include" $CONFIG_BIND || sed -i 's/include/#include/' $CONFIG_BIND
    grep -qF "named.ca" $CONFIG_BIND || sed -i 's/db\.cache/named\.ca/' $CONFIG_BIND
    /etc/init.d/named restart
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
    service cs-services status >/dev/null 2>&1
    [ $? = 1 ] && return 1 || return 0
}
# check whether Rspamd is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_rspamd() {
    service rspamd status >/dev/null 2>&1
    [ $? = 1 ] && return 1 || return 0
}
# check whether ACME Tool is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_letsencrypt() {
    which acmetool >/dev/null 2>&1
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
    which vmware-toolbox-cmd >/dev/null 2>&1
    return $?
}
# check whether local DNS resolver is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_local_dns() {
    RET_CODE=$(grep -qF "dnssec-validation auto;" $CONFIG_BIND || grep -qF "#include" $CONFIG_BIND || grep -qF "named.ca" $CONFIG_BIND)
    return $RET_CODE
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
    EXPLANATION_RSPAMD="Implemented as a milter on Port 11332.\nThe webinterface runs on Port 11334 on localhost.\nYou will need a SSH Tunnel to access the Webinterface.\nssh root@servername -L 11334:127.0.0.1:11334\n\nEnable corresponding feature in menu under 'Enable features->Rspamd'"
    EXPLANATION_LETSENCRYPT="Easy acquisition of Let's Encrypt certificates for TLS. It will autorenew the certificates via cronjob.\n\nEnable corresponding feature in menu under 'Enable features->Let's-Encrypt-Cert'"
    EXPLANATION_LOCAL_DNS="DNS forwarding disabled and local DNSSec resolver enabled for DANE validation.\n\nEnable corresponding feature in menu under 'Enable features->DANE'"
    while [ 1 ]; do
        DIALOG_RSPAMD_INSTALLED="$DIALOG_RSPAMD"
        DIALOG_LETSENCRYPT_INSTALLED="$DIALOG_LETSENCRYPT"
        DIALOG_AUTO_UPDATE_INSTALLED="$DIALOG_AUTO_UPDATE"
        DIALOG_VMWARE_TOOLS_INSTALLED="$DIALOG_VMWARE_TOOLS"
        DIALOG_LOCAL_DNS_INSTALLED="$DIALOG_LOCAL_DNS"
        check_installed_rspamd && DIALOG_RSPAMD_INSTALLED="$DIALOG_RSPAMD_INSTALLED (installed)"
        check_installed_letsencrypt && DIALOG_LETSENCRYPT_INSTALLED="$DIALOG_LETSENCRYPT_INSTALLED (installed)"
        check_installed_auto_update && DIALOG_AUTO_UPDATE_INSTALLED="$DIALOG_AUTO_UPDATE_INSTALLED (installed)"
        check_installed_vmware_tools && DIALOG_VMWARE_TOOLS_INSTALLED="$DIALOG_VMWARE_TOOLS_INSTALLED (installed)"
        check_installed_local_dns && DIALOG_LOCAL_DNS_INSTALLED="$DIALOG_LOCAL_DNS_INSTALLED (installed)"
        exec 3>&1
            DIALOG_RET=$($DIALOG --clear --backtitle "$TITLE_MAIN"              \
                --cancel-label "Back" --ok-label "Apply"                        \
                --menu "Choose features to install" 0 0 0                       \
                "$DIALOG_LOCAL_DNS_INSTALLED" ""                                \
                "$DIALOG_VMWARE_TOOLS_INSTALLED" ""                             \
                "$DIALOG_RSPAMD_INSTALLED" ""                                   \
                "$DIALOG_LETSENCRYPT_INSTALLED" ""                              \
                "$DIALOG_AUTO_UPDATE_INSTALLED" ""                              \
                2>&1 1>&3)
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
            esac
        else
            break
        fi
    done
}
###################################################################################################
# enable features in Postfix custom config
###################################################################################################
# enable Rspamd
# parameters:
# none
# return values:
# none
enable_rspamd() {
    # Clearswift integration as milter
    echo '# Rspamd' >> $PF_IN
    echo 'smtpd_milters=inet:127.0.0.1:11332, inet:127.0.0.1:19127' >> $PF_IN
    echo "mydestination=$(hostname)" >> $PF_IN
    if ! grep -q 'learnspam: "| rspamc learn_spam"' $MAP_ALIASES || ! grep -q 'learnham: "| rspamc learn_ham"' $MAP_ALIASES; then
        grep -q 'learnspam: "| rspamc learn_spam"' $MAP_ALIASES || echo 'learnspam: "| rspamc learn_spam"' >> $MAP_ALIASES
        grep -q 'learnham: "| rspamc learn_ham"' $MAP_ALIASES || echo 'learnham: "| rspamc learn_ham"' >> $MAP_ALIASES
        newaliases
    fi
}
# enable Let's Encrypt cert
# parameters:
# none
# return values:
# none
enable_letsencrypt() {
    if [ -f $DIR_CERT/privkey ] && [ -f $DIR_CERT/fullchain ]; then
        # use Letsencrypt certificates
        echo "# Let's Encrypt cert" >> $PF_IN
        echo "smtpd_tls_key_file=$DIR_CERT/privkey" >> $PF_IN
        echo "smtpd_tls_cert_file=$DIR_CERT/fullchain" >> $PF_IN
        echo "# Let's Encrypt cert" >> $PF_OUT
        echo "smtp_tls_key_file=$DIR_CERT/privkey" >> $PF_OUT
        echo "smtp_tls_cert_file=$DIR_CERT/fullchain" >> $PF_OUT
    else
        $DIALOG --clear --backtitle "Enable features" --msgbox "Let's Encrypt certificates are missing." 0 0
    fi
}
# enable verbose TLS
# parameters:
# none
# return values:
# none
enable_tls() {
    echo '# Verbose TLS' >> $PF_IN
    echo 'smtpd_tls_loglevel=1' >> $PF_IN
    [ -f /etc/postfix/dh1024.pem ] || openssl dhparam -out /etc/postfix/dh1024.pem 1024 >/dev/null 2>&1
    echo 'smtpd_tls_dh1024_param_file=/etc/postfix/dh1024.pem' >> $PF_IN
    echo '# Verbose TLS' >> $PF_OUT
    echo 'smtp_tls_note_starttls_offer=yes' >> $PF_OUT
    echo 'smtp_tls_loglevel=1' >> $PF_OUT
}
# enable ESMTP filter
# parameters:
# none
# return values:
# none
enable_esmtp_filter() {
    echo '# ESMTP filter' >> $PF_IN
    echo "smtpd_discard_ehlo_keyword_address_maps=cidr:$DIR_MAPS/esmtp_access" >> $PF_IN
    echo 'smtpd_discard_ehlo_keywords=' >> $PF_IN
}
# enable DANE
# parameters:
# none
# return values:
# none
enable_dane() {
    echo '# DANE' >> $PF_OUT
    echo 'smtp_tls_security_level=dane' >> $PF_OUT
    echo 'smtp_dns_support_level=dnssec' >> $PF_OUT
}
# enable sender rewrite
# parameters:
# none
# return values:
# none
enable_sender_rewrite() {
    echo '# Sender rewrite' >> $PF_IN
    echo "sender_canonical_maps=regexp:$DIR_MAPS/sender_canonical_maps" >> $PF_IN
}
# enable inbound bounce notification
# parameters:
# $1 - notification email address
# return values:
# none
enable_bounce_in() {
    if [ -z "$1" ]; then
        exec 3>&1
        DIALOG_RET=$(dialog --clear --backtitle "Enable features"                       \
            --title "Inbound bounce notifications"                                      \
            --inputbox "Enter email for inbound bounce notifications" 0 50              \
            $EMAIL_DEFAULT 2>&1 1>&3)
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
    echo '# Inbound bounce notifications' >> $PF_IN
    echo 'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce' >> $PF_IN
    echo "2bounce_notice_recipient=$EMAIL_BOUNCE" >> $PF_IN
    echo "bounce_notice_recipient=$EMAIL_BOUNCE" >> $PF_IN
    echo "delay_notice_recipient=$EMAIL_BOUNCE" >> $PF_IN
    echo "error_notice_recipient=$EMAIL_BOUNCE" >> $PF_IN
    return 0
}
# enable outbound bounce notification
# parameters:
# $1 - notification email address
# return values:
# none
enable_bounce_out() {
    if [ -z "$1" ]; then
        exec 3>&1
        DIALOG_RET=$(dialog --clear --backtitle "Enable features"                       \
            --title "Outbound bounce notifications"                                     \
            --inputbox "Enter email for outbound bounce notifications" 0 50             \
            $EMAIL_DEFAULT 2>&1 1>&3)
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
    echo '# Outbound bounce notifications' >> $PF_OUT
    echo 'notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce' >> $PF_OUT
    echo "2bounce_notice_recipient=$EMAIL_BOUNCE" >> $PF_OUT
    echo "bounce_notice_recipient=$EMAIL_BOUNCE" >> $PF_OUT
    echo "delay_notice_recipient=$EMAIL_BOUNCE" >> $PF_OUT
    echo "error_notice_recipient=$EMAIL_BOUNCE" >> $PF_OUT
    return 0
}
# enable Postscreen
# parameters:
# none
# return values:
# none
enable_postscreen() {
    # Postscreen Master.cf settings
    echo '# Postscreen' >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -M# '25/inet'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -Me '25/inet=25  inet n - n - 1 postscreen'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -Me 'smtpd/pass=smtpd      pass  -       -       n       -       -       smtpd'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -Me 'dnsblog/unix=dnsblog    unix  -       -       n       -       0       dnsblog'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -Me 'tlsproxy/unix=tlsproxy   unix  -       -       n       -       0       tlsproxy'" >> $CONFIG_PF
    # Postscreen main.cf settings
    echo "postconf -c $PF_INBOUND -e 'postscreen_access_list=permit_mynetworks cidr:/etc/postfix/maps/check_postscreen_access_ips'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_blacklist_action=enforce'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_command_time_limit=\${stress?10}\${stress:300}s'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_action=enforce'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_sites=$BLACKLISTS'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_threshold=3'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_ttl=1h'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_greet_action=enforce'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_greet_wait=\${stress?4}\${stress:15}s'" >> $CONFIG_PF
}
# enable Postscreen Deep inspection
# parameters:
# none
# return values:
# none
enable_postscreen_deep() {
# Deep inspection test (might cause delays)
    echo '# Deep Postscreen' >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_enable=yes'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_bare_newline_action=enforce'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_action=enforce'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_non_smtp_command_enable=yes'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_pipelining_enable=yes'" >> $CONFIG_PF
    echo "postconf -c $PF_INBOUND -e 'postscreen_dnsbl_whitelist_threshold=-1'" >> $CONFIG_PF
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
    if [ ! -f $PF_IN ] || ! grep -q '# Rspamd' $PF_IN || ! grep -q 'learnspam: "| rspamc learn_spam"' $MAP_ALIASES || ! grep -q 'learnham: "| rspamc learn_ham"' $MAP_ALIASES; then
        echo off
    else
        echo on
    fi
}
# check whether Let's Encrypt cert is enabled
# parameters:
# none
# return values:
# Let's Encrypt cert status
check_enabled_letsencrypt() {
    if [ ! -f $PF_IN ] || ! grep -q "# Let's Encrypt cert" $PF_IN || [ ! -f $PF_OUT ] || ! grep -q "# Let's Encrypt cert" $PF_OUT ; then
        echo off
    else
        echo on
    fi
}
# check whether verbose TLS is enabled
# parameters:
# none
# return values:
# verbose TLS status
check_enabled_tls() {
    if [ ! -f $PF_IN ] || ! grep -q '# Verbose TLS' $PF_IN || [ ! -f $PF_OUT ] || ! grep -q '# Verbose TLS' $PF_OUT; then
        echo off
    else
        echo on
    fi
}
# check whether ESMTP filter is enabled
# parameters:
# none
# return values:
# ESMTP filter status
check_enabled_esmtp_filter() {
    if [ ! -f $PF_IN ] || ! grep -q '# ESMTP filter' $PF_IN; then
        echo off
    else
        echo on
    fi
}
# check whether DANE is enabled
# parameters:
# none
# return values:
# DANE status
check_enabled_dane() {
    if [ ! -f $PF_OUT ] || ! grep -q '# DANE' $PF_OUT; then
        echo off
    else
        echo on
    fi
}
# check whether sender rewrite is enabled
# parameters:
# none
# return values:
# sender rewrite status
check_enabled_sender_rewrite() {
    if [ ! -f $PF_IN ] || ! grep -q '# Sender rewrite' $PF_IN; then
        echo off
    else
        echo on
    fi
}
# check whether inbound bounce notification is enabled
# parameters:
# none
# return values:
# inbound bounce notification status
check_enabled_bounce_in() {
    if [ ! -f $PF_IN ] || ! grep -q '# Inbound bounce notifications' $PF_IN; then
        echo off
    else
        echo on
    fi
}
# check whether outbound bounce notification is enabled
# parameters:
# none
# return values:
# outbound bounce notification status
check_enabled_bounce_out() {
    if [ ! -f $PF_OUT ] || ! grep -q '# Outbound bounce notifications' $PF_OUT; then
        echo off
    else
        echo on
    fi
}
# check whether Postscreen is enabled
# parameters:
# none
# return values:
# Postscreen status
check_enabled_postscreen() {
    if [ ! -f $CONFIG_PF ] || ! grep -q '# Postscreen' $CONFIG_PF; then
        echo off
    else
        echo on
    fi
}
# check whether Postscreen Deep inspection is enabled
# parameters:
# none
# return values:
# Postscreen Deep inspection status
check_enabled_postscreen_deep() {
    if [ ! -f $CONFIG_PF ] || ! grep -q '# Deep Postscreen' $CONFIG_PF; then
        echo off
    else
        echo on
    fi
}
# get list of features status
# parameters:
# none
# return values:
# list of features status
check_features_enabled() {
    for FEATURE in rspamd letsencrypt tls esmtp_filter dane sender_rewrite bounce_in bounce_out postscreen postscreen_deep; do
        check_enabled_$FEATURE
    done
}
# apply selected postfix switches
# parameters:
# none
# return values:
# none
activate_config() {
    if [ -f $PF_IN ]; then
        while read LINE; do
            if echo "$LINE" | grep -q -v '^#'; then
                postmulti -i postfix-inbound -x postconf -e "$LINE"
            fi
        done < $PF_IN
    fi
    if [ -f $PF_OUT ]; then
        while read LINE; do
            if echo "$LINE" | grep -q -v '^#'; then
                postmulti -i postfix-outbound -x postconf -e "$LINE"
            fi
        done < $PF_OUT
    fi
    postfix stop >/dev/null 2>&1
    postfix start >/dev/null 2>&1
}
###################################################################################################
# select features to enable in dialog checkbox
# parameters:
# none
# return values:
# none
dialog_enable() {
    DIALOG_RSPAMD="Rspamd"
    DIALOG_LETSENCRYPT="Let's-Encrypt-Cert"
    DIALOG_TLS="Verbose-TLS"
    DIALOG_ESMTP_FILTER="ESMTP-filter"
    DIALOG_DANE="DANE"
    DIALOG_SENDER_REWRITE="Sender-rewrite"
    DIALOG_BOUNCE_IN="Inbound-Bounce"
    DIALOG_BOUNCE_OUT="Outbound-Bounce"
    DIALOG_POSTSCREEN="Postscreen"
    DIALOG_POSTSCREEN_DEEP="Postscreen-Deep"
    SETTINGS_START="############# CUSTOM SETTINGS FROM MENU.SH (DO NOT MANUALLY EDIT THIS BLOCK) ##############"
    SETTINGS_END="########## END OF CUSTOM SETTINGS FROM MENU.SH (DO NOT MANUALLY EDIT THIS BLOCK) ##########"
    FEATURES_ENABLED="$(check_features_enabled)"
    EMAIL_BOUNCE_IN=""
    EMAIL_BOUNCE_OUT=""
    [ $(echo $FEATURES_ENABLED | awk '{print $7}') = "on" ] && EMAIL_BOUNCE_IN="$(grep '^bounce_notice_recipient=' $PF_IN | awk -F\= '{print $2}' | tr -d \')"
    [ $(echo $FEATURES_ENABLED | awk '{print $8}') = "on" ] && EMAIL_BOUNCE_OUT="$(grep '^bounce_notice_recipient=' $PF_OUT | awk -F\= '{print $2}' | tr -d \')"
    ARRAY=()
    check_installed_rspamd && ARRAY+=("$DIALOG_RSPAMD" "" $(echo $FEATURES_ENABLED | awk '{print $1}'))
    check_installed_letsencrypt && ARRAY+=("$DIALOG_LETSENCRYPT" "" $(echo $FEATURES_ENABLED | awk '{print $2}'))
    ARRAY+=("$DIALOG_TLS" "" $(echo $FEATURES_ENABLED | awk '{print $3}'))
    ARRAY+=("$DIALOG_ESMTP_FILTER" "" $(echo $FEATURES_ENABLED | awk '{print $4}'))
    check_installed_local_dns && ARRAY+=("$DIALOG_DANE" "" $(echo $FEATURES_ENABLED | awk '{print $5}'))
    ARRAY+=("$DIALOG_SENDER_REWRITE" "" $(echo $FEATURES_ENABLED | awk '{print $6}'))
    ARRAY+=("$DIALOG_BOUNCE_IN" "" $(echo $FEATURES_ENABLED | awk '{print $7}'))
    ARRAY+=("$DIALOG_BOUNCE_OUT" "" $(echo $FEATURES_ENABLED | awk '{print $8}'))
    ARRAY+=("$DIALOG_POSTSCREEN" "" $(echo $FEATURES_ENABLED | awk '{print $9}'))
    ARRAY+=("$DIALOG_POSTSCREEN_DEEP" "" $(echo $FEATURES_ENABLED | awk '{print $10}'))
    exec 3>&1
    DIALOG_RET=$($DIALOG --clear --backtitle "$TITLE_MAIN"                                   \
        --cancel-label "Back" --ok-label "Apply"                                             \
        --checklist "Choose features to enable" 0 0 0                                        \
        "${ARRAY[@]}" 2>&1 1>&3)
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        SETTINGS_IN=""
        SETTINGS_OUT=""
        [ -f $PF_IN ] && SETTINGS_IN="$(sed "/^$SETTINGS_START/,/^$SETTINGS_END/d;/^$SETTINGS_END/q" $PF_IN)"
        [ -f $PF_OUT ] && SETTINGS_OUT="$(sed "/^$SETTINGS_START/,/^$SETTINGS_END/d;/^$SETTINGS_END/q" $PF_OUT)"
        rm -f $PF_IN $PF_OUT
        echo "$SETTINGS_START" >> $PF_IN
        echo "$SETTINGS_START" >> $PF_OUT
        echo '#!/bin/bash' > $CONFIG_PF
        LIST_ENABLED=""
        for FEATURE in $DIALOG_RET; do
            case "$FEATURE" in
                \"$DIALOG_RSPAMD\")
                    enable_rspamd
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"Rspamd";;
                \"$DIALOG_LETSENCRYPT\")
                    enable_letsencrypt
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"Let's Encrypt cert";;
                \"$DIALOG_TLS\")
                    enable_tls
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"Verbose TLS";;
                \"$DIALOG_ESMTP_FILTER\")
                    enable_esmtp_filter
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"ESMTP filter";;
                \"$DIALOG_DANE\")
                    enable_dane
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"DANE";;
                \"$DIALOG_SENDER_REWRITE\")
                    enable_sender_rewrite
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"Sender rewrite";;
                \"$DIALOG_BOUNCE_IN\")
                    enable_bounce_in "$EMAIL_BOUNCE_IN" && LIST_ENABLED="$LIST_ENABLED"$'\n'"Inbound-Bounce";;
                \"$DIALOG_BOUNCE_OUT\")
                    enable_bounce_out "$EMAIL_BOUNCE_OUT" && LIST_ENABLED="$LIST_ENABLED"$'\n'"Outbound-Bounce";;
                \"$DIALOG_POSTSCREEN\")
                    enable_postscreen
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"Postscreen";;
                \"$DIALOG_POSTSCREEN_DEEP\")
                    enable_postscreen_deep
                    LIST_ENABLED="$LIST_ENABLED"$'\n'"Postscreen Deep";;
            esac
        done
        if ! [[ $DIALOG_RET = *\"$DIALOG_RSPAMD\"* ]]; then
            if grep -q 'learnspam: "| rspamc learn_spam"' $MAP_ALIASES || grep -q 'learnham: "| rspamc learn_ham"' $MAP_ALIASES; then
                sed -i '/^learnspam: "| rspamc learn_spam"$/d' $MAP_ALIASES
                sed -i '/^learnham: "| rspamc learn_ham"$/d' $MAP_ALIASES
                newaliases
            fi
            postmulti -i postfix-inbound -x postconf mydestination | grep -q "$(hostname)" && postmulti -i postfix-inbound -x postconf -e mydestination=
        fi
        [ -z "$LIST_ENABLED" ] && LIST_ENABLED="$LIST_ENABLED"$'\n'"None"
        echo "$SETTINGS_END" >> $PF_IN
        [ -z "$SETTINGS_IN" ] || echo "$SETTINGS_IN" >> $PF_IN
        echo "$SETTINGS_END" >> $PF_OUT
        [ -z "$SETTINGS_OUT" ] || echo "$SETTINGS_OUT" >> $PF_OUT
        chown -R cs-admin:cs-adm /opt/cs-gateway/custom
        FEATURES_ENABLED_NEW="$(check_features_enabled)"
        for COUNTER in $(seq 1 8); do
            if [ "$(echo $FEATURES_ENABLED | awk "{print $"$COUNTER"}")" = "on" ] &&
                [ "$(echo $FEATURES_ENABLED_NEW | awk "{print $"$COUNTER"}")" = "off" ]; then
                APPLY_NEEDED=1
                break
            fi
        done
        for COUNTER in $(seq 9 10); do
            if ! [ "$(echo $FEATURES_ENABLED | awk "{print $"$COUNTER"}")" = "$(echo $FEATURES_ENABLED_NEW | awk "{print $"$COUNTER"}")" ]; then
                APPLY_NEEDED=1
                break
            fi
        done
        if [ $APPLY_NEEDED = 1 ]; then
            LIST_ENABLED="$LIST_ENABLED"$'\n\n'"IMPORTANT: Apply configuration in main menu to activate."
        else
            LIST_ENABLED="$LIST_ENABLED"$'\n'" "
            activate_config
        fi
        $DIALOG --backtitle "$TITLE_MAIN" --title "Enabled features" --clear --msgbox "$LIST_ENABLED" 0 0
    fi
}
###################################################################################################
# some custom settings
###################################################################################################
# edit LDAP schedule
# parameters:
# none
# return values:
# none
ldap_schedule() {
    TMP_LDAP="/tmp/TMPldap"
    TMP_LDAP_OLD="/tmp/TMPldap_old"
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
    DIALOG_RET=$(dialog --clear --backtitle "Manage SSH access"             \
        --title "Add allowed IP/-range"                                     \
        --inputbox "Enter allowed IP/-range for SSH access" 0 50 2>&1 1>&3)
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
    while [ 1 ]; do
        LIST_IP=""
        [ -f $CONFIG_FW ] && LIST_IP=$(grep "I INPUT 4 -i eth0 -p tcp --dport 22 -s " $CONFIG_FW | awk '{print $11}')
        if [ -z "$LIST_IP" ]; then
            add_ssh || break
        else
            ARRAY=()
            for IP_ADDRESS in $LIST_IP; do
                ARRAY+=($IP_ADDRESS "")
            done
            exec 3>&1
            DIALOG_RET=$($DIALOG --clear --backtitle "" --title "Manage configuration"                  \
                    --cancel-label "Back" --ok-label "Add" --extra-button --extra-label "Remove"        \
                    --menu "Add/remove IPs for SSH access" 0 0 0                                        \
                    "${ARRAY[@]}" 2>&1 1>&3)
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_ssh
            else
                if [ $RET_CODE = 3 ]; then
                    sed -i "/-I INPUT 4 -i eth0 -p tcp --dport 22 -s $(echo "$DIALOG_RET" | sed 's/\//\\\//g') -j ACCEPT/d" $CONFIG_FW
                    iptables -D INPUT -i eth0 -p tcp --dport 22 -s $DIALOG_RET -j ACCEPT
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
    DIALOG_RET="$(dialog --clear --backtitle "Manage SSH key authentication"  \
        --title "Add public SSH key"                                          \
        --inputbox "Enter public key for SSH authentication for cs-admin" 0 50 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        if ! grep -qF "^PubkeyAuthentication yes" /etc/ssh/sshd_config                    ||
            ! grep -qF "^AuthorizedKeysFile .ssh/authorized_keys" /etc/ssh/sshd_config ]  ||
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
    while [ 1 ]; do
        LIST_KEY=""
        [ -f $SSH_KEYS ] && LIST_KEY=$(sed 's/ /,/g' $SSH_KEYS)
        if [ -z "$LIST_KEY" ]; then
            add_key || break
        else
            ARRAY=()
            for SSH_KEY in $LIST_KEY; do
                ARRAY+=("$(echo $SSH_KEY | sed 's/,/ /g')" "")
            done
            exec 3>&1
            DIALOG_RET=$($DIALOG --clear --backtitle "" --title "Manage configuration"                  \
                    --cancel-label "Back" --ok-label "Add" --extra-button --extra-label "Remove"        \
                    --menu "Add/remove public keys for SSH authentication for cs-admin" 0 0 0           \
                    "${ARRAY[@]}" 2>&1 1>&3)
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
    TMP_KEYSTORE="/tmp/TMPkeystore"
    exec 3>&1
    DIALOG_RET=$(dialog --clear --backtitle "Manage configuration"                                                 \
        --title "Import PKCS12 keystore"                                                                              \
        --inputbox "Enter filename of keystore to import [Note: keystore password must be '$PASSWORD_KEYSTORE']" 0 50 2>&1 1>&3)
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ] && [ -f $DIALOG_RET ]; then
        keytool -importkeystore -destkeystore $TMP_KEYSTORE -srckeystore $DIALOG_RET -srcstoretype pkcs12 -deststorepass $PASSWORD_KEYSTORE -srcstorepass $PASSWORD_KEYSTORE >/dev/null 2>&1
        if [ $? = 0 ]; then
            mv /var/cs-gateway/keystore /var/cs-gateway/keystore.old
            mv $TMP_KEYSTORE /var/cs-gateway/keystore
            cs-servicecontrol restart tomcat >/dev/null 2>&1
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
# export address lists from CS config
# parameters:
# none
# return values:
# none
export_address_list() {
    cd /home/cs-admin
    mkdir -p $DIR_ADDRESS_LISTS
    LIST_EXPORTED="Address lists exported to '$DIR_ADDRESS_LISTS':\n"
    while read LINE
    do
        if [ ! -z "$LINE" ]; then
            NAME_LIST=$(echo "$LINE" | awk -F "type=" '{print $1}' | awk -F "name=\"" '{print $2}' | tr -d \" | sed 's/ /_/g' | sed 's/_$//g')
            get_addr "$LINE" > $DIR_ADDRESS_LISTS/"$NAME_LIST".lst
            LIST_EXPORTED="$LIST_EXPORTED\n$NAME_LIST.lst"
        fi
    done < <(get_addr_list "$1")
    chown -R cs-admin:cs-adm $DIR_ADDRESS_LISTS
    $DIALOG --backtitle "Clearswift Configuration" --title "Export address lists" --clear --msgbox "$LIST_EXPORTED" 0 0
}
# toggle password check for cs-admin
# parameters:
# none
# return values:
# none
toggle_password() {
    if grep -q "cs-admin ALL=(ALL) NOPASSWD:ALL" /etc/sudoers && grep -q "^\s*sudo su -s" /opt/csrh/cli/climenu; then
        STATUS_CURRENT="disabled"
        STATUS_TOGGLE="Enable"
    else
        STATUS_CURRENT="enabled"
        STATUS_TOGGLE="Disable"
    fi
    exec 3>&1
    $DIALOG --backtitle "Clearswift Configuration" --title "Toggle CS admin password check"         \
        --yesno "CS admin password check is currently $STATUS_CURRENT. $STATUS_TOGGLE?" 0 60        \
        2>&1 1>&3
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        if [ $STATUS_CURRENT = "disabled" ]; then
            sed -i '/cs-admin ALL=(ALL) NOPASSWD:ALL/d' /etc/sudoers
            sed -i '/^\s*sudo su -s/s/sudo su -s/su -s/g' /opt/csrh/cli/climenu
        else
            grep -q "cs-admin ALL=(ALL) NOPASSWD:ALL" /etc/sudoers || echo "cs-admin ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
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
    PACKED_SCRIPT="
    H4sIAL8b3FsAA22PS0vDQBSF9/MrrkkXLZpM2pUoBUMbasEICnElhMn0JhnM3KnzUIP43w0+cOPi                                                                                                     
    wIHD98GJT3ijiDfC9YzFIAcUttbPAQOmroeHZZqlGYunaWOOo1Vd72EuF7DKludwi35jCCryaAl7                                                                                                     
    jeQatMIH6mCnm+szIPTSUDLFhcEr6lJp9JcuD7439gJKYSVsFdonhwRznR5++tW/7IKx7f6+Lu+q                                                                                                     
    oirWEX8RlkuXdMLjqxi5Fmrg7mjMwL9P1CZ4HrEy39/U+a5YrxhrFR0gmv1pIkj8eERoIdFeaYTT                                                                                                     
    aPYLTBu+oQSrIWnh/QMeL9knhMlH1DQBAAA=
    "

    if [ -f "$CRON_CLEANUP" ]; then
        STATUS_CURRENT="enabled"
        STATUS_TOGGLE="Disable"
    else
        STATUS_CURRENT="disabled"
        STATUS_TOGGLE="Enable"
    fi
    exec 3>&1
    $DIALOG --backtitle "Clearswift Configuration" --title "Toggle CS mqueue cleanup"         \
        --yesno "CS mqueue cleanup is currently $STATUS_CURRENT. $STATUS_TOGGLE?" 0 60        \
        2>&1 1>&3
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        if [ $STATUS_CURRENT = "disabled" ]; then
            printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > $CRON_CLEANUP
            chmod 700 $CRON_CLEANUP
        else
            rm -f $CRON_CLEANUP
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
    DIALOG_RET=$(dialog --clear --backtitle "Manage mail.intern access"     \
        --title "Add mail server IP to mail.intern"                         \
        --inputbox "Enter mail server IP for mail.intern" 0 50 2>&1 1>&3)
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
    while [ 1 ]; do
        LIST_IP=""
        [ -f $CONFIG_INTERN ] && LIST_IP=$(grep "^mail" $CONFIG_INTERN | awk '{print $5}')
        if [ -z "$LIST_IP" ]; then
            add_mail || break
        else
            ARRAY=()
            for IP_ADDRESS in $LIST_IP; do
                ARRAY+=($IP_ADDRESS "")
            done
            exec 3>&1
            DIALOG_RET=$($DIALOG --clear --backtitle "" --title "Manage configuration"                  \
                    --cancel-label "Back" --ok-label "Add" --extra-button --extra-label "Remove"        \
                    --menu "Add/remove IPs for mail.intern" 0 0 0                                       \
                    "${ARRAY[@]}" 2>&1 1>&3)
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
    DIALOG_RET=$(dialog --clear --backtitle "Internal DNS forwarding"       \
        --title "Add zone for internal DNS forwarding"                      \
        --inputbox "Enter zone name" 0 50 2>&1 1>&3)
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
        ZONE_NAME="$DIALOG_RET"
        exec 3>&1
        DIALOG_RET=$(dialog --clear --backtitle "Internal DNS forwarding"       \
            --title "Add zone for internal DNS forwarding"                      \
            --inputbox "Enter IP" 0 50 2>&1 1>&3)
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
            echo "zone \"$ZONE_NAME\" {" >> $CONFIG_BIND
            echo '    type forward;' >> $CONFIG_BIND
    	    echo "    forwarders { $DIALOG_RET; };" >> $CONFIG_BIND
            echo '    forward only;' >> $CONFIG_BIND
            echo '};' >> $CONFIG_BIND
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
    while [ 1 ]; do
        LIST_FORWARD=""
        if [ -f $CONFIG_BIND ]; then
            ZONE_NAME=""
            while read LINE; do
                if echo "$LINE" | grep -q '^zone ".*" {$'; then
                    ZONE_NAME="$(echo $LINE | awk 'match($0, /^zone "(.*)" {$/, a) {print a[1]}')"
                    ZONE_IP=""
                fi
                if ! [ -z "$ZONE_NAME" ] && echo "$LINE" | grep -q '^\s*forwarders { \S*; };$'; then
                    LIST_FORWARD+=" $ZONE_NAME($(echo $LINE | awk 'match($0, /forwarders { (.*); };$/, a) {print a[1]}'))"
                    ZONE_NAME=""
                fi
            done < <(sed -n '/^zone ".*" {$/,/^}$/p' $CONFIG_BIND)
        fi
        if [ -z "$LIST_FORWARD" ]; then
            add_forward || break
        else
            ARRAY=()
            for ZONE_FORWARD in $LIST_FORWARD; do
                ARRAY+=($ZONE_FORWARD "")
            done
            exec 3>&1
            DIALOG_RET=$($DIALOG --clear --backtitle "" --title "Manage configuration"                  \
                    --cancel-label "Back" --ok-label "Add" --extra-button --extra-label "Remove"        \
                    --menu "Add/remove zones for internal DNS forwarding" 0 0 0                         \
                    "${ARRAY[@]}" 2>&1 1>&3)
            RET_CODE=$?
            exec 3>&-
            if [ $RET_CODE = 0 ]; then
                add_forward
            else
                if [ $RET_CODE = 3 ]; then
                    sed -i "/zone \"$(echo $DIALOG_RET | awk -F\( '{print $1}')\" {/,/^}/d" $CONFIG_BIND
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
    DIALOG_RET="$(dialog --clear --backtitle "Monthly email stats reports"      \
        --title "Add recipient email for report"                                \
        --inputbox "Enter recipient email for monthly reports" 0 50 2>&1 1>&3)"
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
    while [ 1 ]; do
        LIST_EMAIL=""
        [ -f $CRON_STATS ] && LIST_EMAIL=$(grep "^$SCRIPT_STATS" $CRON_STATS | awk '{print $2}')
        if [ -z "$LIST_EMAIL" ]; then
            add_report || break
        else
            ARRAY=()
            for EMAIL_ADDRESS in $LIST_EMAIL; do
                ARRAY+=("$EMAIL_ADDRESS" "")
            done
            exec 3>&1
            DIALOG_RET=$($DIALOG --clear --backtitle "" --title "Email recipients"                      \
                    --cancel-label "Back" --ok-label "Add" --extra-button --extra-label "Remove"        \
                    --menu "Add/remove emails for monthly email stats reports" 0 0 0                    \
                    "${ARRAY[@]}" 2>&1 1>&3)
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
    DIALOG_RET="$(dialog --clear --backtitle "Sender anomaly detection"         \
        --title "Add recipient email for anomaly alert"                         \
        --inputbox "Enter recipient email for anomaly alert" 0 50 2>&1 1>&3)"
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
    while [ 1 ]; do
        LIST_EMAIL=""
        [ -f $CRON_ANOMALY ] && LIST_EMAIL=$(grep "^30 1,7,13,19 \* \* \* root $SCRIPT_ANOMALY" $CRON_ANOMALY | awk '{print $8}')
        if [ -z "$LIST_EMAIL" ]; then
            add_alert || break
        else
            ARRAY=()
            for EMAIL_ADDRESS in $LIST_EMAIL; do
                ARRAY+=("$EMAIL_ADDRESS" "")
            done
            exec 3>&1
            DIALOG_RET=$($DIALOG --clear --backtitle "" --title "Email recipients"                      \
                    --cancel-label "Back" --ok-label "Add" --extra-button --extra-label "Remove"        \
                    --menu "Add/remove emails for monthly email stats reports" 0 0 0                    \
                    "${ARRAY[@]}" 2>&1 1>&3)
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
# get list of recipient validation status
# parameters:
# none
# return values:
# list of recipient validation status
check_validation_enabled() {
    LINE_VALIDATION=""
    [ -f $PF_IN ] && LINE_VALIDATION="$(grep 'smtpd_recipient_restrictions=check_client_access cidr:/etc/postfix/maps/check_client_access_ips, check_sender_access regexp:/etc/postfix/maps/check_sender_access, check_recipient_access regexp:/etc/postfix/maps/check_recipient_access, check_helo_access regexp:/etc/postfix/maps/check_helo_access' $PF_IN)"
    for VALIDATION in unknown_client invalid_hostname non_fqdn_hostname unknown_reverse_client_hostname non_fqdn_helo_hostname   \
        invalid_helo_hostname unknown_helo_hostname non_fqdn_sender unknown_sender_domain unknown_recipient_domain               \
        non_fqdn_recipient unauth_pipelining unverified_recipient
    do
        if [ -z "$LINE_VALIDATION" ] || ! [[ $LINE_VALIDATION = *"reject_$VALIDATION"* ]]; then
            echo off
        else
            echo on
        fi
    done
}
# select recipient validation to enable in dialog checkbox
# parameters:
# none
# return values:
# none
recipient_validation() {
    DIALOG_UNKNOWN_CLIENT="unknown_client"
    DIALOG_INVALID_HOSTNAME="invalid_hostname"
    DIALOG_NON_FQDN_HOSTNAME="non_fqdn_hostname"
    DIALOG_UNKNOWN_REVERSE_CLIENT_HOSTNAME="unknown_reverse_client_hostname"
    DIALOG_NON_FQDN_HELO_HOSTNAME="non_fqdn_helo_hostname"
    DIALOG_INVALID_HELO_HOSTNAME="invalid_helo_hostname"
    DIALOG_UNKNOWN_HELO_HOSTNAME="unknown_helo_hostname"
    DIALOG_NON_FQDN_SENDER="non_fqdn_sender"
    DIALOG_UNKNOWN_SENDER_DOMAIN="unknown_sender_domain"
    DIALOG_UNKNOWN_RECIPIENT_DOMAIN="unknown_recipient_domain"
    DIALOG_NON_FQDN_RECIPIENT="non_fqdn_recipient"
    DIALOG_UNAUTH_PIPELINING="unauth_pipelining"
    DIALOG_UNVERIFIED_RECIPIENT="unverified_recipient"
    VALIDATION_ENABLED="$(check_validation_enabled)"
    exec 3>&1
    DIALOG_RET=$($DIALOG --clear --backtitle "Clearswift configuration"                                \
        --cancel-label "Back" --ok-label "Apply"                                                       \
        --checklist "Choose recipient rejection criteria" 0 0 0                                        \
        "$DIALOG_UNKNOWN_CLIENT" ""                   $(echo $VALIDATION_ENABLED | awk '{print $1}')   \
        "$DIALOG_INVALID_HOSTNAME" ""                 $(echo $VALIDATION_ENABLED | awk '{print $2}')   \
        "$DIALOG_NON_FQDN_HOSTNAME" ""                $(echo $VALIDATION_ENABLED | awk '{print $3}')   \
        "$DIALOG_UNKNOWN_REVERSE_CLIENT_HOSTNAME" ""  $(echo $VALIDATION_ENABLED | awk '{print $4}')   \
        "$DIALOG_NON_FQDN_HELO_HOSTNAME" ""           $(echo $VALIDATION_ENABLED | awk '{print $5}')   \
        "$DIALOG_INVALID_HELO_HOSTNAME" ""            $(echo $VALIDATION_ENABLED | awk '{print $6}')   \
        "$DIALOG_UNKNOWN_HELO_HOSTNAME" ""            $(echo $VALIDATION_ENABLED | awk '{print $7}')   \
        "$DIALOG_NON_FQDN_SENDER" ""                  $(echo $VALIDATION_ENABLED | awk '{print $8}')   \
        "$DIALOG_UNKNOWN_SENDER_DOMAIN" ""            $(echo $VALIDATION_ENABLED | awk '{print $9}')   \
        "$DIALOG_UNKNOWN_RECIPIENT_DOMAIN" ""         $(echo $VALIDATION_ENABLED | awk '{print $10}')  \
        "$DIALOG_NON_FQDN_RECIPIENT" ""               $(echo $VALIDATION_ENABLED | awk '{print $11}')  \
        "$DIALOG_UNAUTH_PIPELINING" ""                $(echo $VALIDATION_ENABLED | awk '{print $12}')  \
        "$DIALOG_UNVERIFIED_RECIPIENT" ""             $(echo $VALIDATION_ENABLED | awk '{print $13}')  \
        2>&1 1>&3)
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        if [ -f $PF_IN ]; then
            sed -i '/# Recipient validation/d' $PF_IN
            sed -i '/smtpd_recipient_restrictions=/d' $PF_IN
            sed -i '/smtpd_delay_reject=yes/d' $PF_IN
            sed -i '/smtpd_helo_required=yes/d' $PF_IN
            sed -i '/address_verify_transport_maps=/d' $PF_IN
            sed -i '/address_verify_map=/d' $PF_IN
            sed -i '/address_verify_map=/d' $PF_OUT
        fi
        if ! [ -z "$DIALOG_RET" ]; then
            LIST_ENABLED='smtpd_recipient_restrictions=check_client_access cidr:/etc/postfix/maps/check_client_access_ips, check_sender_access regexp:/etc/postfix/maps/check_sender_access, check_recipient_access regexp:/etc/postfix/maps/check_recipient_access, check_helo_access regexp:/etc/postfix/maps/check_helo_access'
            for FEATURE in $DIALOG_RET; do
                case "$FEATURE" in
                    \"$DIALOG_UNKNOWN_CLIENT\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_UNKNOWN_CLIENT";;
                    \"$DIALOG_INVALID_HOSTNAME\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_INVALID_HOSTNAME";;
                    \"$DIALOG_NON_FQDN_HOSTNAME\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_NON_FQDN_HOSTNAME";;
                    \"$DIALOG_UNKNOWN_REVERSE_CLIENT_HOSTNAME\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_UNKNOWN_REVERSE_CLIENT_HOSTNAME";;
                    \"$DIALOG_NON_FQDN_HELO_HOSTNAME\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_NON_FQDN_HELO_HOSTNAME";;
                    \"$DIALOG_INVALID_HELO_HOSTNAME\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_INVALID_HELO_HOSTNAME";;
                    \"$DIALOG_UNKNOWN_HELO_HOSTNAME\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_UNKNOWN_HELO_HOSTNAME";;
                    \"$DIALOG_NON_FQDN_SENDER\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_NON_FQDN_SENDER";;
                    \"$DIALOG_UNKNOWN_SENDER_DOMAIN\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_UNKNOWN_SENDER_DOMAIN";;
                    \"$DIALOG_UNKNOWN_RECIPIENT_DOMAIN\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_UNKNOWN_RECIPIENT_DOMAIN";;
                    \"$DIALOG_NON_FQDN_RECIPIENT\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_NON_FQDN_RECIPIENT";;
                    \"$DIALOG_UNAUTH_PIPELINING\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_UNAUTH_PIPELINING";;
                    \"$DIALOG_UNVERIFIED_RECIPIENT\")
                        LIST_ENABLED="$LIST_ENABLED, reject_$DIALOG_UNVERIFIED_RECIPIENT";;
                esac
            done
            echo "$LIST_ENABLED" >> $PF_IN
            if [[ $DIALOG_RET = *\"$DIALOG_UNVERIFIED_RECIPIENT\"* ]]; then
                echo 'address_verify_transport_maps=hash:/etc/postfix-outbound/transport.map' >> $PF_IN
                echo 'address_verify_map=' >> $PF_IN
                echo 'address_verify_map=' >> $PF_OUT
            fi
            echo 'smtpd_delay_reject=yes' >> $PF_IN
            echo 'smtpd_helo_required=yes' >> $PF_IN
        fi    
        VALIDATION_ENABLED_NEW="$(check_validation_enabled)"
        for COUNTER in $(seq 1 13); do
            if ! [ "$(echo $VALIDATION_ENABLED | awk "{print $"$COUNTER"}")" = "$(echo $VALIDATION_ENABLED_NEW | awk "{print $"$COUNTER"}")" ]; then
                activate_config
                break
            fi
        done
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
    [ -d $DIR_MAPS ] || mkdir -p $DIR_MAPS
    if [ ! -f $WHITELIST_POSTSCREEN ]; then
        echo '######################################################################' >> $WHITELIST_POSTSCREEN
        echo '# IPs vom postscreen ausschliessen, Whitelisten (Monitoring Systeme) #' >> $WHITELIST_POSTSCREEN
        echo '######################################################################' >> $WHITELIST_POSTSCREEN
        echo '#NetCon (CIDR)' >> $WHITELIST_POSTSCREEN
        echo '#88.198.215.226 permit' >> $WHITELIST_POSTSCREEN
        echo '#85.10.249.206  permit' >> $WHITELIST_POSTSCREEN
    fi
    if [ ! -f $WHITELIST_POSTFIX ]; then
        echo '############################################################' >> $WHITELIST_POSTFIX
        echo '# IP-Adressen erlauben, die ein seltsames Verhalten zeigen #' >> $WHITELIST_POSTFIX
        echo '############################################################' >> $WHITELIST_POSTFIX
        echo '# Postfix IP Whitelist (CIDR)' >> $WHITELIST_POSTFIX
        echo '#1.2.3.4  REJECT unwanted newsletters!' >> $WHITELIST_POSTFIX
        echo '#1.2.3.0/24  OK' >> $WHITELIST_POSTFIX
    fi
    if [ ! -f $SENDER_ACCESS ]; then
        echo '##########################################' >> $SENDER_ACCESS
        echo '# Postfix Sender Email Blacklist (REGEXP)#' >> $SENDER_ACCESS
        echo '# bestimmte Domains von Extern ablehnen  #' >> $SENDER_ACCESS
        echo '##########################################' >> $SENDER_ACCESS
        echo '#/.*@isdoll\.de$/                       REJECT mydomain in your envelope sender not allowed! Use your own domain!' >> $SENDER_ACCESS
    fi
    if [ ! -f $RECIPIENT_ACCESS ]; then
        echo '#############################################' >> $RECIPIENT_ACCESS
        echo '# Postfix Recipient Email Blacklist (REJECT)#' >> $RECIPIENT_ACCESS
        echo '# bestimmte Empfaenger ablehnen             #' >> $RECIPIENT_ACCESS
        echo '#############################################' >> $RECIPIENT_ACCESS
        echo '#/mueller@isdoll\.de$/                  REJECT user has moved!' >> $RECIPIENT_ACCESS
    fi
    if [ ! -f $HELO_ACCESS ]; then
        echo '#######################################' >> $HELO_ACCESS
        echo '# Postfix Helo Blacklist (REGEXP)     #' >> $HELO_ACCESS
        echo '# HELO String des Mailservers pruefen #' >> $HELO_ACCESS
        echo '#######################################' >> $HELO_ACCESS
    fi
    if [ ! -f $ESMTP_ACCESS ]; then
        echo '##################################' >> $ESMTP_ACCESS
        echo '# Postfix ESMTP Verbs            #' >> $ESMTP_ACCESS
        echo '# remove unnecessary ESMTP Verbs #' >> $ESMTP_ACCESS
        echo '##################################' >> $ESMTP_ACCESS
        echo '#130.180.71.126/32      silent-discard, auth' >> $ESMTP_ACCESS
        echo '#212.202.158.254/32     silent-discard, auth' >> $ESMTP_ACCESS
        echo '#0.0.0.0/0              silent-discard, etrn, enhancedstatuscodes, dsn, pipelining, auth' >> $ESMTP_ACCESS
    fi
    if [ ! -f $HEADER_REWRITE ]; then
        echo '#####################################' >> $HEADER_REWRITE
        echo '# Postfix Outbound Header Rewriting #' >> $HEADER_REWRITE
        echo '#####################################' >> $HEADER_REWRITE
        echo '#/^\s*Received: from \S+ \(\S+ \[\S+\]\)(.*)/ REPLACE Received: from [127.0.0.1] (localhost [127.0.0.1])$1' >> $HEADER_REWRITE
        echo '#/^\s*User-Agent/        IGNORE' >> $HEADER_REWRITE
        echo '#/^\s*X-Enigmail/        IGNORE' >> $HEADER_REWRITE
        echo '#/^\s*X-Mailer/          IGNORE' >> $HEADER_REWRITE
        echo '#/^\s*X-Originating-IP/  IGNORE' >> $HEADER_REWRITE
    fi
    if [ ! -f $SENDER_REWRITE ]; then
        echo '#############################' >> $SENDER_REWRITE
        echo '# fix broken sender address #' >> $SENDER_REWRITE
        echo '#############################' >> $SENDER_REWRITE
        echo '#/^<.*>(.*)@(.*)>/   ${1}@${2}' >> $SENDER_REWRITE
    fi
}
###################################################################################################
# select Postfix configuration to edit in dialog menu
# parameters:
# none
# return values:
# none
dialog_postfix() {
    DIALOG_WHITELIST_POSTFIX="Postfix whitelist"
    DIALOG_WHITELIST_POSTSCREEN="Postscreen whitelist"
    DIALOG_ESMTP_ACCESS="ESMTP access"
    DIALOG_SENDER_ACCESS="Sender access"
    DIALOG_RECIPIENT_ACCESS="Recipient access"
    DIALOG_HELO_ACCESS="HELO access"
    DIALOG_SENDER_REWRITE="Sender rewrite"
    DIALOG_HEADER_REWRITE="Header rewrite"
    DIALOG_RESTRICTIONS="Postfix restrictions"
    while [ 1 ]; do
        exec 3>&1
        DIALOG_RET=$($DIALOG --clear --backtitle "$TITLE_MAIN"                                  \
            --cancel-label "Back" --ok-label "Edit" --menu "Manage Postfix configuration" 0 0 0 \
            "$DIALOG_WHITELIST_POSTFIX" ""                                                      \
            "$DIALOG_WHITELIST_POSTSCREEN" ""                                                   \
            "$DIALOG_ESMTP_ACCESS" ""                                                           \
            "$DIALOG_SENDER_ACCESS" ""                                                          \
            "$DIALOG_RECIPIENT_ACCESS" ""                                                       \
            "$DIALOG_HELO_ACCESS" ""                                                            \
            "$DIALOG_SENDER_REWRITE" ""                                                         \
            "$DIALOG_HEADER_REWRITE" ""                                                         \
            "$DIALOG_RESTRICTIONS" ""                                                           \
            2>&1 1>&3)
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_WHITELIST_POSTFIX")
                    $TXT_EDITOR $WHITELIST_POSTFIX;;
                "$DIALOG_WHITELIST_POSTSCREEN")
                    $TXT_EDITOR $WHITELIST_POSTSCREEN;;
                "$DIALOG_ESMTP_ACCESS")
                    $TXT_EDITOR $ESMTP_ACCESS;;
                "$DIALOG_SENDER_ACCESS")
                    $TXT_EDITOR $SENDER_ACCESS;;
                "$DIALOG_RECIPIENT_ACCESS")
                    $TXT_EDITOR $RECIPIENT_ACCESS;;
                "$DIALOG_HELO_ACCESS")
                    $TXT_EDITOR $HELO_ACCESS;;
                "$DIALOG_SENDER_REWRITE")
                    $TXT_EDITOR $SENDER_REWRITE;;
                "$DIALOG_HEADER_REWRITE")
                    $TXT_EDITOR $HEADER_REWRITE;;
                "$DIALOG_RESTRICTIONS")
                    dialog_restrictions;;
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
    DIALOG_RECIPIENT="Recipient restrictions"
    while [ 1 ]; do
        exec 3>&1
        DIALOG_RET=$($DIALOG --clear --backtitle "$TITLE_MAIN"                                  \
            --cancel-label "Back" --ok-label "Edit" --menu "Manage Postfix restrictions" 0 0 0  \
            "$DIALOG_RECIPIENT" ""                                                              \
            2>&1 1>&3)
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
    DIALOG_CUSTOM_COMMANDS="Custom commands"
    DIALOG_LDAP="LDAP schedule"
    DIALOG_SSH="SSH access"
    DIALOG_KEY_AUTH="SSH key authentication for cs-admin"
    DIALOG_IMPORT_KEYSTORE="Import PKCS12 for Tomcat"
    DIALOG_EXPORT_ADDRESS="Export address lists"
    DIALOG_TOGGLE_PASSWORD="Toggle CS admin password check"
    DIALOG_TOGGLE_CLEANUP="Toggle mqueue cleanup"
    while [ 1 ]; do
        exec 3>&1
        DIALOG_RET=$($DIALOG --clear --backtitle "$TITLE_MAIN"                                     \
            --cancel-label "Back" --ok-label "Edit" --menu "Manage Clearswift configuration" 0 0 0 \
            "$DIALOG_CUSTOM_COMMANDS" ""                                                           \
            "$DIALOG_LDAP" ""                                                                      \
            "$DIALOG_SSH" ""                                                                       \
            "$DIALOG_KEY_AUTH" ""                                                                  \
            "$DIALOG_IMPORT_KEYSTORE" ""                                                           \
            "$DIALOG_EXPORT_ADDRESS" ""                                                            \
            "$DIALOG_TOGGLE_PASSWORD" ""                                                           \
            "$DIALOG_TOGGLE_CLEANUP" ""                                                            \
            2>&1 1>&3)
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_CUSTOM_COMMANDS")
                    cd $DIR_COMMANDS
                    $TXT_EDITOR .
                    cd -;;
                "$DIALOG_LDAP")
                    ldap_schedule;;
                "$DIALOG_SSH")
                    ssh_access;;
                "$DIALOG_KEY_AUTH")
                    key_auth;;
                "$DIALOG_IMPORT_KEYSTORE")
                    import_keystore;;
                "$DIALOG_EXPORT_ADDRESS")
                    export_address_list;;
                "$DIALOG_TOGGLE_PASSWORD")
                    toggle_password;;
                "$DIALOG_TOGGLE_CLEANUP")
                    toggle_cleanup;;
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
    while [ 1 ]; do
        [ -f $SCRIPT_STATS ] && [ -f $CRON_STATS ] && STATUS_CRON="enabled" || STATUS_CRON="disabled"
        ARRAY=()
        ARRAY+=("$DIALOG_STATUS$STATUS_CRON" "")
        if [ "$STATUS_CRON" = "enabled" ]; then
            ARRAY+=("$DIALOG_EMAIL" "")
            ARRAY+=("$DIALOG_SCRIPT" "")
        fi
        exec 3>&1
        DIALOG_RET=$($DIALOG --clear --backtitle "Other configurations"                         \
            --cancel-label "Back" --ok-label "Edit" --menu "Monthly email stats reports" 0 40 0 \
            "${ARRAY[@]}" 2>&1 1>&3)
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
    while [ 1 ]; do
        [ -f $SCRIPT_ANOMALY ] && [ -f $CRON_ANOMALY ] && STATUS_CRON="enabled" || STATUS_CRON="disabled"
        ARRAY=()
        ARRAY+=("$DIALOG_STATUS$STATUS_CRON" "")
        if [ "$STATUS_CRON" = "enabled" ]; then
            ARRAY+=("$DIALOG_EMAIL" "")
            ARRAY+=("$DIALOG_SCRIPT" "")
        fi
        exec 3>&1
        DIALOG_RET=$($DIALOG --clear --backtitle "Other configurations"                         \
            --cancel-label "Back" --ok-label "Edit" --menu "Sender anomaly detection" 0 40 0    \
            "${ARRAY[@]}" 2>&1 1>&3)
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_STATUS$STATUS_CRON")
                    if [ "$STATUS_CRON" = "enabled" ]; then
                        rm -f $SCRIPT_ANOMALY $CRON_ANOMALY
                    else
                        PACKED_SCRIPT="
                        H4sIACma8lsAA61WbVPiSBD+nl/RjrGSiCHA1lbdqVCyHl5xJWoBXq0FSA1kgLlLJlwyiK5wv/16
                        kkiCsPrlUlrMS3dP9/P0dM/hgTPiwhnRaKYdwqXHaBgt+URCp/E7eMEUqKDeyw8W4u79kkEn8H0W
                        ghnFvxeCyXEgbPyPFp7kYlocB76FsuWSUymVf9EOcYxmJtxjMAlCkIFLX7R0pUqcJxo6OHPGkT2l
                        ki3pi+NT7hV108UpFMjRg33k20cusYooR9CcT59ByURAPS9YMhfm6FHEhIs/aqhOaNW/D1v15nWn
                        +rVUimftxmXzrtm46eKS1m3dDes3t6369QM6If25gytUBD4GSzQ+gR7YP4DoZQKDM5AzJjTAj41n
                        AZD7iE7ZKegmosYE9RnoJQuY8skO2ZjPOROSJArPXEJZm/CcTRM9198wqdQclz05YuF51r6zRBCz
                        EMvSJzyBjjyWs11Rtg9BL4MNm7PVQgUXfBYpVzWFzZB6LJSmBa+xcuv7sNNo/9loVxFpPoVCNAtC
                        CQURuCKK2Bj8Zwww8QFRWAFd/g32FbkgYLzOQy4kHrE2LFhBpBRtEeJQooNglyER3xKMT81A2Jy/
                        HXQW+JgKEUgMXLgx20hw+MRCkomp8L/EU4QgU9QrBM+PVewISE83Z0EkFU3WAOoJxeAyycaSB4KA
                        3YHIl/NqzqfTyldcDyGnepGNwXatGBRtrXVv71Dn5jfEEYmdhmwOxhzlJvzZDhZyFCyEa2Rsr2IJ
                        MgkDv3qObiYo4b0webV8xs+rN1dnvFCwXhEoU+fwLziJrIO8pWDy9XptwCrCvDeit21niksyRNeA
                        9GsnJN13HnXHVcKKotVC8H/AHqfTmLEZoy4SZqU5f5CQk0W1zc7NfSu9VGlq5CTfc17e4lzfqII9
                        xd3N9dxhP4fo54dsEivWbLYaw0633rpTXCTl4+jKyjImyb6JCjC7/rv5pz6Fns2BIICZWXCIcaDo
                        zKlvaWFxaT8MvzWubtuNTT6Qx17J/tUe9AtbkZAtMzkv1adkhvXrRrtbJds72Q3KH7Y/iNydyAWR
                        dyKjhUCt9vPA3vlU3tpkXsR2pJXhDIiEx7zH75n8gkySHStxtEr/eR5u5VAySUxh3fwkp/YxGyG1
                        eYeczzFyyMcIfYiS+tI6tWe6g+H/w9teb3LHpqmUiWEiwWoFWcNIeiDpJN3VyDlhwIxGSlLmmUka
                        c9zli+StOOPfdbPTHbbur7tNldHLmaqGoSo+8Vpq8gzcINbp3H/7o3HZ3aQO1uacGIG3dgRGj5CB
                        sV0QkmOzqvyJBWxo+/QzhwtV3egLI4EJwe/jKPGvj6G4gWBwDufvij8Xce13xviiEot58XhJQ4Hv
                        o1NQJVe9Vxajv7AFnea7Q3IlfCrHM1MvnYDzMyUwi8cWqNoPzglQC3I6kLQEs/cIg2OrpgRGm+5B
                        0GXaKw/U78kIB6qVJB18BZv+kG/pyiXSx/dFLblh2TPqzWZfL62JpaW5lOH2cS5FsORyBn4QMrys
                        VOxY37xmolOSEpCzrf0H/3XBVbkKAAA=
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
# select other configuration to manage in dialog menu
# parameters:
# none
# return values:
# none
dialog_other() {
    DIALOG_WHITELIST_RSPAMD="Rspamd whitelist"
    DIALOG_AUTO_UPDATE="Auto-update"
    DIALOG_MAIL_INTERN="Mail.intern RoundRobin"
    DIALOG_CONFIG_FW="Firewall settings"
    DIALOG_RECENT_UPDATES="Recently updated packages"
    DIALOG_FORWARDING="Internal DNS forwarding"
    DIALOG_REPORT="Monthly email stats reports"
    DIALOG_ANOMALY="Sender anomaly detection"
    while [ 1 ]; do
        exec 3>&1
        DIALOG_RET=$($DIALOG --clear --backtitle "$TITLE_MAIN"                                   \
            --cancel-label "Back" --ok-label "Edit" --menu "Manage other configuration" 0 40 0   \
            "$DIALOG_WHITELIST_RSPAMD" ""                                                        \
            "$DIALOG_AUTO_UPDATE" ""                                                             \
            "$DIALOG_MAIL_INTERN" ""                                                             \
            "$DIALOG_CONFIG_FW" ""                                                               \
            "$DIALOG_RECENT_UPDATES" ""                                                          \
            "$DIALOG_FORWARDING" ""                                                              \
            "$DIALOG_REPORT" ""                                                                  \
            "$DIALOG_ANOMALY" ""                                                                 \
            2>&1 1>&3)
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
            case "$DIALOG_RET" in
                "$DIALOG_WHITELIST_RSPAMD")
                    $TXT_EDITOR $WHITELIST_RSPAMD;;
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
    ARRAY=()
    LIST_RELAY="$(grep 'smtp:\[.*\]' $MAP_TRANSPORT | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
    for NAME_RELAY in $LIST_RELAY; do
        COUNTER=0
        FOUND=""
        for COLLECTED in "${ARRAY[@]}"; do
            if [ "$NAME_RELAY" = "$(echo $COLLECTED | awk '{print $1}')" ]; then
                ARRAY[$COUNTER]="$NAME_RELAY $(expr $(echo $COLLECTED | awk '{print $2}') + 1)"
                FOUND=1
            fi
            COUNTER="$(expr $COUNTER + 1)"
        done
        [ -z "$FOUND" ] && ARRAY+=("$NAME_RELAY 1")
    done
    MOST_FREQUENT=""
    for COLLECTED in "${ARRAY[@]}"; do
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
    while [ 1 ]; do
        exec 3>&1
        DIALOG_RET=$($DIALOG --clear --backtitle "$TITLE_MAIN"                                        \
            --cancel-label "Back" --ok-label "Edit" --menu "Postfix infos & stats" 0 40 0             \
            "$DIALOG_NEW_SETTINGS" ""                                                                 \
            "$DIALOG_GENERAL" ""                                                                      \
            "$DIALOG_TLS_IN" ""                                                                       \
            "$DIALOG_TLS_OUT" ""                                                                      \
            "$DIALOG_LOG" ""                                                                          \
            2>&1 1>&3)
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
# commit selected configuration to CS
# parameters:
# none
# return values:
# none
apply_config() {
    DOM="https://$(hostname -I | sed 's/ //')/"
    SESSION_ID=""
    if [ -f $TMP_PASSWORD ]; then
        OUTPUT_CURL="$(curl -k -i -d "pass=$(cat $TMP_PASSWORD)&submitted=true&userid=admin" -X POST "$DOM"Appliance/index.jsp --silent)"
        if echo "$OUTPUT_CURL" | grep -q 'Sorry, the account you are attempting to access is locked due to unsuccessful login attempts.' ||         \
            echo "$OUTPUT_CURL" | grep -q 'Sorry, the user name or password you supplied is invalid or you do not have permission to log in.'; then
            rm -f $TMP_PASSWORD
        else
            SESSION_ID="$(echo "$OUTPUT_CURL" | grep 'Set-Cookie: JSESSIONID=' | awk '{print $2}')"
        fi
    fi
    if [ -z "$SESSION_ID" ]; then
        exec 3>&1
        DIALOG_RET=$(dialog --clear --backtitle "$TITLE_MAIN"              \
            --title "Apply configuration"                                  \
            --passwordbox "Enter CS admin password" 0 50 2>&1 1>&3)
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ] && [ ! -z "$DIALOG_RET" ]; then
            OUTPUT_CURL="$(curl -k -i -d "pass=$DIALOG_RET&submitted=true&userid=admin" -X POST "$DOM"Appliance/index.jsp --silent)"
            if echo "$OUTPUT_CURL" | grep -q 'Sorry, the account you are attempting to access is locked due to unsuccessful login attempts.'; then
                $DIALOG --clear --backtitle "$TITLE_MAIN" --msgbox "Too many incorrect login attempts. Account locked. Try again in 10m." 0 0
            else
                if echo "$OUTPUT_CURL" | grep -q 'Sorry, the user name or password you supplied is invalid or you do not have permission to log in.'; then
                    $DIALOG --clear --backtitle "$TITLE_MAIN" --msgbox "Incorrect password." 0 0
                else
                    SESSION_ID="$(echo "$OUTPUT_CURL" | grep 'Set-Cookie: JSESSIONID=' | awk '{print $2}')"
                    echo "$DIALOG_RET" > $TMP_PASSWORD
                fi
            fi
        fi
    fi
    if [ ! -z "$SESSION_ID" ]; then
        curl -k -i -d "policy=true&system=true&pmm=true&proxy=true&peers=true&users=true&reports=true&tlsCertificates=true&maintenance=true&detail='command line applied bei NetCon GUI'&reason=764c31c0-8d6a-4bf2-ab22-44d61b6784fb&planned=yes&items=" \
        	--header "Cookie: $SESSION_ID" -X POST ${DOM}/Appliance/Deployer/StartDeployment.jsp
        APPLY_NEEDED=0
    fi
}
###################################################################################################
init_cs() {
    # enable CS RHEL repo
    [ -f /etc/yum.repos.d/cs-rhel-mirror.repo ] && sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/cs-rhel-mirror.repo
    # create custom settings dirs
    mkdir -p /opt/cs-gateway/custom/postfix-{inbound,outbound}
    touch $CONFIG_PF
    chmod +x $CONFIG_PF
    chown cs-admin:cs-adm $CONFIG_PF
    grep -q $CONFIG_PF $PF_CUSTOMISE || echo $'\n'"$CONFIG_PF" >> $PF_CUSTOMISE
    head -1 $CONFIG_PF | grep -q '^#!/bin/bash' || echo '#!/bin/bash' >> $CONFIG_PF
    grep -qF '*filter' "$CONFIG_FW" || echo '*filter' >> "$CONFIG_FW"
    grep -qF ':INPUT DROP [0:0]' "$CONFIG_FW" || echo ':INPUT DROP [0:0]' >> "$CONFIG_FW"
    grep -qF ':FORWARD DROP [0:0]' "$CONFIG_FW" || echo ':FORWARD DROP [0:0]'  >> "$CONFIG_FW"
    grep -qF ':OUTPUT DROP [0:0]' "$CONFIG_FW" || echo ':OUTPUT DROP [0:0]' >> "$CONFIG_FW"
    chown -R cs-admin:cs-adm /opt/cs-gateway/custom
    # create alias shortcuts for menu and Mail Logs
    grep -qF 'alias pflogs' /root/.bashrc || echo 'alias pflogs="tail -f /var/log/cs-gateway/mail.$(date +%Y-%m-%d).log"' >> /root/.bashrc
    grep -qF "Return to CS menu with 'exit'" /home/cs-admin/.bash_profile || echo "echo -e $'\n'\"\e[91m===============================\"$'\n'\" Return to CS menu with 'exit'\"$'\n'\"===============================\e[0m\"$'\n'" >> /home/cs-admin/.bash_profile
    # write example custom command
    EXAMPLE_COMMAND="$DIR_COMMANDS/example_script.sh"
    if [ ! -f $EXAMPLE_COMMAND ]; then
        echo '!/bin/bash' >> $EXAMPLE_COMMAND
        echo 'filename=$1' >> $EXAMPLE_COMMAND
        echo 'LOG_FILE=/var/log/cs-gateway/removetxt.log' >> $EXAMPLE_COMMAND
        echo 'touch $LOG_FILE' >> $EXAMPLE_COMMAND
        echo >> $EXAMPLE_COMMAND
        echo 'if grep -iFq "#encrypt" $filename; then' >> $EXAMPLE_COMMAND
        echo '        sed -i 's/#encrypt#//g' "$filename"' >> $EXAMPLE_COMMAND
        echo '        echo "Found encrypt text.. Removed it..done" $filename >>  $LOG_FILE' >> $EXAMPLE_COMMAND
        echo '        exit 5' >> $EXAMPLE_COMMAND
        echo 'else' >> $EXAMPLE_COMMAND
        echo '        exit 0' >> $EXAMPLE_COMMAND
        echo >> $EXAMPLE_COMMAND
        echo 'fi' >> $EXAMPLE_COMMAND
        chown cs-admin:cs-adm $EXAMPLE_COMMAND
        chmod +x $EXAMPLE_COMMAND
    fi
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
        INFO_END=$(expr $(grep -n '# Todo:' $0 | head -1 | awk -F: '{print $1}') - 2)
        INFO_TEXT="$(sed -n "$INFO_START,"$INFO_END"p" $0 | sed 's/^#//g' | sed 's/^ //g')"
        exec 3>&1
        $DIALOG --clear --backtitle "$TITLE_MAIN" --title "Program info" --ok-label "ESC to not show again / Enter to continue" --msgbox "$INFO_TEXT" 0 0 2>&1 1>&3
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE != 0 ]; then
            touch $TMP_INFO
        fi
    fi
}
# check for update and when available ask user whether to install it and show changelog
# parameters:
# none
# return values:
# none
check_update() {
    TMP_UPDATE="/tmp/TMPupdate"
    wget $LINK_UPDATE -O $TMP_UPDATE >/dev/null 2>&1
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
        exec 3>&1
        $DIALOG --clear --backtitle "$TITLE_MAIN" --yesno "New update available. Install?" 0 40 2>&1 1>&3
        RET_CODE=$?
        exec 3>&-
        if [ $RET_CODE = 0 ]; then
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
grep -qF "alias menu=/root/menu.sh" /root/.bashrc || echo "alias menu=/root/menu.sh" >> /root/.bashrc
check_installed_seg && init_cs
write_examples
check_update
print_info
DIALOG_SEG="Install Clearswift SEG"
DIALOG_INSTALL="Install features"
DIALOG_ENABLE="Enable features"
DIALOG_POSTFIX="Postfix configs"
DIALOG_CLEARSWIFT="Clearswift configs"
DIALOG_OTHER="Other configs"
DIALOG_SHOW="Postfix infos & stats"
DIALOG_APPLY="Apply configuration"
while [ 1 ]; do
    ARRAY=()
    if check_installed_seg; then
        ARRAY+=("$DIALOG_INSTALL" "")
        ARRAY+=("$DIALOG_ENABLE" "")
        ARRAY+=("$DIALOG_POSTFIX" "")
        ARRAY+=("$DIALOG_CLEARSWIFT" "")
        ARRAY+=("$DIALOG_OTHER" "")
        ARRAY+=("$DIALOG_SHOW" "")
        [ $APPLY_NEEDED = 1 ] && ARRAY+=("$DIALOG_APPLY" "")
    else
        ARRAY+=("$DIALOG_SEG" "")
    fi
    exec 3>&1
    DIALOG_RET=$($DIALOG --clear --title "$TITLE_MAIN $VERSION_MENU"           \
        --cancel-label "Exit" --menu "" 0 0 0 \
        "${ARRAY[@]}" 2>&1 1>&3)
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        case "$DIALOG_RET" in
            "$DIALOG_SEG")
                install_seg;;
            "$DIALOG_INSTALL")
                dialog_install;;
            "$DIALOG_ENABLE")
                dialog_enable;;
            "$DIALOG_POSTFIX")
                dialog_postfix;;
            "$DIALOG_CLEARSWIFT")
                dialog_clearswift;;
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