#!/bin/bash
# Author: Uwe Sommer
# sommer@netcon-consulting.com
scp menu.sh nc-www:/var/www/www.netcon-consulting.com
scp -P 20022 menu.sh root@pxe.isdoll.de:/var/www/html

