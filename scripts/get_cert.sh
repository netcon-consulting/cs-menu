#!/bin/bash

. /etc/profile.d/cs-vars.sh

/opt/cs-gateway/bin/cs-servicecontrol stop tomcat
/opt/cs-gateway/bin/cs-servicecontrol stop pmm
/sbin/service httpd stop

/sbin/iptables -I INPUT 4 -p tcp -m tcp --dport 80 -j ACCEPT

/root/.acme.sh/acme.sh --cron --home /root/.acme.sh

/sbin/iptables -D INPUT -p tcp -m tcp --dport 80 -j ACCEPT

cp -f /root/.acme.sh/__HOST_NAME__/__HOST_NAME__.cer /etc/ssl/__HOST_NAME__.cer
cp -f /root/.acme.sh/__HOST_NAME__/__HOST_NAME__.key /etc/ssl/__HOST_NAME__.key
cp -f /root/.acme.sh/__HOST_NAME__/fullchain.cer /etc/ssl/fullchain.cer

openssl pkcs12 -export -name tomcat -in /etc/ssl/__HOST_NAME__.cer -inkey /etc/ssl/__HOST_NAME__.key -out /root/keystore.p12 -passout pass:changeit
keytool -importkeystore -destkeystore /var/cs-gateway/keystore -srckeystore /root/keystore.p12 -srcstoretype pkcs12 -deststorepass changeit -srcstorepass changeit

/opt/cs-gateway/bin/cs-servicecontrol start tomcat
/opt/cs-gateway/bin/cs-servicecontrol start pmm
