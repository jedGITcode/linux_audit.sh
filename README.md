# linux_audit.sh
Bash Linux auditing script pulls from system logs

Linux Auditing

logs_location must be set before first run !!!!!!!

Some Event are limited to a given hosts Set "backup server" to move logs to backup server/location. 
Set "Ansible Master" hostname to report on ansible commands

Events must be configured in auditd. 
Basic STIG audit rules + Custom EXP:
          -a always,exit -F path=/usr/bin/ansible -F perms=xwr -F auid>1000 auid!=4294967295 -k ansible
