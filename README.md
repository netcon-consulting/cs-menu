NetCon Clearswift Configuration V1.92.0
=======================================

Config tool for missing features on Clearswift Secure E-Mail Gateway. These settings will ease many advanced configuration tasks and highly improve spam detection. Everything is in this single dialog file, which should be run as root.

<p align="center">
  <img src="https://raw.githubusercontent.com/netcon-consulting/cs-menu/master/images/SEG.png">
</p>

## Features:

### Clearswift:
* Letsencrypt certificates via ACME installation and integration
* install latest VMware Tools from VMware repo
* custom LDAP schedule
* easy extraction of address lists from last clearswift policy
* custom firewall rules for SSH access with CIDR support
* change Tomcat SSL certificate for web administration
* SSH Key authentication for cs-admin
* removed triple authentication for cs-admin when becoming root
* reconfigure local DNS Resolver without forwarders and DNSSec support
* apply configuration in bash to activate customisations
* aliases for quick log access and menu config (pflogs, menu)
* sample custom commands for "run external command" content rule
* automatic mail queue cleanup
* automatic daily CS config backup via mail
* Hybrid-Analysis Falcon and Palo Alto Networks WildFire sandbox integration
* import 'run external command' policy rules
* install external commands including corresponding policy rules
* generate base policy configuration
* setup outbound-bounce archive
* LDAP-sync monitoring

### Postfix settings:
* Postscreen weighted blacklists and bot detection for Postfix
* Postscreen deep protocol inspection (optional)
* Postfix verbose TLS logging
* Postfix recipient verification via next transport hop
* DANE support for Postfix (outbound)
* outbound header rewriting (anonymising)
* loadbalancing for Postfix transport rules (multi destination transport)
* custom individual outbound settings (override general main.cf options)
* Postfix notifications for rejected, bounced or error mails
* custom Postfix ESMTP settings (disable auth and DSN silently)
* advanced smtpd recipient restrictions and whitelists
* smtpd late reject to identify senders of rejected messages
* Office365 IP-range whitelisting
* sender dependent routing
* milter bypass

### Rspamd:
* Rspamd installation and integration as milter
* master-slave cluster setup
* feature toggles for greylisting, rejecting, Bayes-learning, detailed spam headers, detailed Rspamd history, URL reputation and phishing detection
* integration of Heinlein Spamassassin rules with automatic daily updates
* integration of Pyzor and Razor
* automatic Rspamd updates
* integration of Elasticsearch logging
* management of various white-/blacklists
