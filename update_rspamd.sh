#!/bin/bash

# update_rspamd.sh V1.1.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

TRANSPORT_MAP='/etc/postfix-outbound/transport.map'

EMAIL_RECIPIENT='uwe@usommer.de'

yum check-update rspamd &>/dev/null
if [ "$?" != 0 ]; then
    yum update -y rspamd &>/dev/null
    if [ "$?" = 0 ]; then
        PACKED_SCRIPT='
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
        printf "%s" $PACKED_SCRIPT | base64 -d | gunzip > /etc/init.d/rspamd

        MESSAGE_EMAIL="Rspamd successfully updated to version '$(yum list rspamd | grep rspamd | awk '{print $2}')'"
    else
        MESSAGE_EMAIL='Error updating rspamd'
    fi
    DOMAIN_RECIPIENT="$(echo "$EMAIL_RECIPIENT"| awk -F"@" '{print $2}')"
    MAIL_RELAY=''
    [ -f "$TRANSPORT_MAP" ] && MAIL_RELAY="$(grep "^$DOMAIN_RECIPIENT " $TRANSPORT_MAP | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
    [ -z "$MAIL_RELAY" ] && MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
    if [ -z "$MAIL_RELAY" ]; then
        echo "Cannot determine mail relay"
        exit 1
    else
        echo "$MESSAGE_EMAIL" | mail -s "[Rspamd-update] $MESSAGE_EMAIL" -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) "$EMAIL_RECIPIENT"
    fi
fi
