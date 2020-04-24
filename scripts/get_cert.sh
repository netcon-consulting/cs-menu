#!/bin/bash

. /etc/profile.d/cs-vars.sh

/opt/cs-gateway/bin/cs-servicecontrol stop tomcat
/opt/cs-gateway/bin/cs-servicecontrol stop pmm
/sbin/service httpd stop
/sbin/iptables -I INPUT 4 -p tcp -m tcp --dport 80 -j ACCEPT

/root/.acme.sh/acme.sh --cron --home /root/.acme.sh

/sbin/iptables -D INPUT -p tcp -m tcp --dport 80 -j ACCEPT
/opt/cs-gateway/bin/cs-servicecontrol start tomcat
/opt/cs-gateway/bin/cs-servicecontrol start pmm
