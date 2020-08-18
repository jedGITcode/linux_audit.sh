#!/bin/bash
################################################################################
# linux_audit.sh 
#
#
#   Author: Justin E Davis  2020    Justin Davis AT jedconsulting DOT net
################################################################################

# Variables
#!!!!!!!!!!!!!!!!!!!
#!  Must Set !!!!!
#!!!!!!!!!!!!!!!!!!!
####logs_location="/"
log_file="$logs_location/audit_ISSM$(date +"%F".log)"
todays_date=$(date +%Y%m%d)

################################################################################
# Check if the script is being run as root/superuser via sudo
################################################################################
root_check() {
  if [ "$EUID" -ne "0" ]; then
    err "Script must be run as root, try sudo"
  fi
}

################################################################################
#last report
################################################################################
last_report() {
  msg "Last Report"
  msg "$(last)"
}

################################################################################
#lastb report
################################################################################
lastb_report() {
  msg "Lastb Report"
  msg "$(lastb)"
}

################################################################################
#aureport anomaly
#
#  Args:
#       -n           : anomaly
#       --summary    : Rummary report
#       --key        : Report on key
#       --au         : Authentication 
#       -m           : Account Modifications
#       --avc        : AVC messages
#       -n           : Anomaly
#       -r           : Anomaly response 
#       -k           : Key
#
################################################################################
aureport_report() {
  #Vars
  args1=$1
  args2=$2

  msg "Aureport $args1  $args2"
  msg "$(aureport --input-logs -ts week-ago $args1 $args2)"
}

################################################################################
#faillock report
################################################################################
faillock_report() {
  msg "Faillock Report"
  msg "$(faillock)"
}

################################################################################
#Disk space report
################################################################################
disk_space_report() {
  msg "Disk Space Report"
  msg "$(df -h)"
}

################################################################################
#Sudo command report
################################################################################
sudo_command_report() {
  msg "Sudo Command Report"
  tempFile=$(mktemp /tmp/logfile.XXXXXX)
  ausearch --input-logs -ts week-ago -c sudo > $tempFile
  IDS=$(ausearch --input-logs -i -if $tempFile | grep -A 1 a0=sudo \
      | cut -d')' -f 1 | rev | cut -d':' -f1 | rev  | grep -v "\-\-" | uniq)
  msg "$(ausearch_filter "sudo" $tempFile ${IDS[@]})"
  rm $tempFile
}

################################################################################
#Mount command report
################################################################################
mount_command_report() {
  msg "Mount Command Report"
  tempFile=$(mktemp /tmp/logfile.XXXXXX)
  ausearch --input-logs -ts week-ago -c mount > $tempFile
  IDS=$(ausearch --input-logs -i -if $tempFile | grep a0=mount \
      | cut -d')' -f 1 | rev | cut -d':' -f1 | rev  | grep -v "\-\-" | uniq)
  msg "$(ausearch_filter "mount" $tempFile ${IDS[@]})"
  rm $tempFile
}

################################################################################
#Ansible command report
################################################################################
ansible_command_report() {
  # Only run on Ansible Master, only system ansible should be run from
  if [ "$HOSTNAME" == "Ansible Master" ]; then
    msg "Ansible Command Report"   
    tempFile=$(mktemp /tmp/logfile.XXXXXX)
    ausearch --input-logs -ts week-ago -c ansible > $tempFile
    #Custom parsing
    IDS=$(ausearch --input-logs -i -if $tempFile \
        | cut -d')' -f 1 | rev | cut -d':' -f1 | rev  | grep -v "\-\-" | uniq)
    OUTPUT=""
    for i in $IDS
    do
      IDDATE=$(ausearch --input-logs -a $i -i -if $tempFile | grep $i | head -n 1 | cut -d'(' -f 2 | cut -d ')' -f1)
      IDCOMMAND=$(ausearch --input-logs -a $i -i -if $tempFile | grep "proctitle=" | rev | cut -d ':' -f1 | rev | cut -d'=' -f 2-20)
      IDUSER=$(ausearch --input-logs -a $i -i -if $tempFile | grep auid | sed 's/auid=/?/g' | cut -d'?' -f2 | cut -d' ' -f1)

      OUTPUT="$OUTPUT\n    $IDUSER $IDDATE\n        $IDCOMMAND\n    ------------------------------\n"
    done

  msg "$OUTPUT"
  rm $tempFile
  fi 
}

################################################################################
#Ausearch Filter
################################################################################
ausearch_filter() {
  #Vars
  commandfilter=$1
  logfile=$2
  IDSa=${@:3}
  
  OUTPUT=""
  for i in $IDSa
  do
    IDDATE=$(ausearch --input-logs -a $i -if $logfile -i | grep $i | head -n 1 | cut -d'(' -f 2 | cut -d ')' -f1)
    IDCOMMAND=$(ausearch --input-logs -a $i -i -if $logfile | grep "a0=$commandfilter" | rev | cut -d ':' -f1 | rev | cut -d'=' -f 3-20 | sed  's/a[1-9]=//g')
    IDUSER=$(ausearch --input-logs -a $i -i -if $logfile | grep auid | sed 's/auid=/?/g' | cut -d'?' -f2 | cut -d' ' -f1)

    OUTPUT="$OUTPUT\n    $IDUSER $IDDATE\n        $IDCOMMAND\n    ------------------------------\n"
  done

  echo -e "$OUTPUT"
}

################################################################################
#Aide report
################################################################################
aide_report() {
  msg "Aide Report"
  msg "$(aide --check)"
}

################################################################################
#Log Rotate and Backup
################################################################################
log_rotate_backup() {
  #Vars
 
  msg "Rotating Logs"
  logrotate -f /etc/logrotate.conf
  pkill -x -10 auditd


  # Backup logs on backup Server, Other systems back logs to Backup Server 
  # with rsyslog 
  if [ "$HOSTNAME" == "Backup Server" ]; then
    cp /var/log/aide/aide.log-$todays_date $logs_location/working/ 
    cp /var/log/messages-$todays_date $logs_location/working/
    cp /var/log/cron-$todays_date $logs_location/working/
    cp /var/log/secure-$todays_date $logs_location/working/
    cp /var/log/maillog-$todays_date $logs_location/working/
  fi

  #Backup other log files
  cp /var/log/yum.log-$todays_date $logs_location/working/yum-$HOSTNAME-$todays_date
  cp /var/log/btmp-$todays_date $logs_location/working/btmp-$HOSTNAME-$todays_date
  cp /var/log/wtmp-$todays_date $logs_location/working/wtmp-$HOSTNAME-$todays_date
  # Audit max size set so only audit.log.1 that was just rotated contains all logs
  cp /var/log/audit/audit.log.1 $logs_location/working/audit-$HOSTNAME-$todays_date
  
  msg "Logs moved to $logs_location/working/"
}

################################################################################
# System msg with date
################################################################################
msg() {
  echo -e "[$(date +'%Y-%m-%d %H:%M:%S%z')]:$HOSTNAME:$0:\n    $@\n\n" >&1
  echo -e "[$(date +'%Y-%m-%d %H:%M:%S%z')]:$HOSTNAME:$0:\n    $@\n\n" &>> $log_file
}

################################################################################
# Error msg and exit with date
################################################################################
err() {
  echo -e "[$(date +'%Y-%m-%d %H:%M:%S%z')]:$HOSTNAME:$0:\n    $@\n\n" >&2
  echo -e "[$(date +'%Y-%m-%d %H:%M:%S%z')]:$HOSTNAME:$0:\n    $@\n\n" &>> $log_file
  exit 1;
}

################################################################################
# Main control loop
#
#   Args:
################################################################################
main() {
  msg "Starting Linux Audit Script\n
################################################################################\n
################################################################################\n
################################################################################\n\n
$HOSTNAME\n\n
################################################################################\n
################################################################################\n
################################################################################"

  ##audit
  root_check
  aureport_report "--summary"
  aureport_report "--summary" "--key"
  aureport_report "-au"
  last_report
  faillock_report
  aureport_report "-m"
  aureport_report "--avc"
  aureport_report "-n"
  aureport_report "-r" 
  ansible_command_report
  sudo_command_report
  mount_command_report
  aide_report
  disk_space_report

  ##back backup
  log_rotate_backup

  msg "Audit Script Complete"
}

################################################################################
# Start main.
################################################################################
main
