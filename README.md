NetCon Clearswift Configuration V1.9.0
======================================

Config tool for missing features on Clearswift Secure E-Mail Gateway. These settings will ease many advanced configuration tasks and highly improve spam detection. Everything is in this single dialog file, which should be run as root!

<p align="center">
  <img src="https://raw.githubusercontent.com/netcon-consulting/nam/master/images/SEG.png">
</p>

## Features:

### Clearswift:
* Letsencrypt certificates via ACME installation and integration to SEG
* install latest vmware Tools from vmware Repo
* custom LDAP schedule for Clearswift SEG
* easy extraction of address lists from last clearswift policy
* custom firewall rules for SSH access with CIDR support
* change Tomcat SSL certificate for web administration
* SSH Key authentication for cs-admin
* removed triple authentication for cs-admin when becoming root
* reconfigure local DNS Resolver without forwarders and DNSSec support
* editable DNS A record for mail.intern (mutiple IP destinations)
* apply configuration in bash to get all customisations work
* aliases for quick log access and menu config (pflogs, menu)
* sample custom command for "run external command" content rule

### Postfix settings:
* Postscreen weighted blacklists and Bot detection for Postfix
* Postscreen deep protocol inspection (optional)
* postfix verbose TLS logging
* Postfix recipient verification via next transport hop
* DANE support for Postfix (outbound)
* outbound header rewriting (anonymising)
* Loadbalancing for Postfix transport rules (multi destination transport)
* custom individual outbound settings (override general main.cf options)
* postfix notifications for rejected, bounced or error mails
* custom Postfix ESMTP settings (disable auth and DSN silently)
* advanced smtpd recipient restrictions and whitelists
* smtpd delay reject to identify senders of rejected messages

### Addons:
* rspamd installation and milter integration
