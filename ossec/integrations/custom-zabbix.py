#!/usr/bin/env python3
#
import subprocess
import sys
import os
import json
from datetime import datetime

zabbix_server = "5.5.5.5"
wazuh_name = "CX Wazuh"
integration_log = "/var/ossec/logs/integrations.log"

usermod_events = ["adduser", "account_changed"]
groupmod_events =["group_changed", "win_group_changed", "group_created", "win_group_created", "group_deleted", "win_group_deleted"]
misp_events = [100722]
failedlogin5_events =[60203, 60204, 60205, 5712, 5719, 5720, 5763, 5758]
failedlogin_events = [111018, 111020, 2501, 5503, 120001, 120005, 120006, 113002, 113003]
lockuser_events =[60115]
shutdown_events = [61105]
exclude_events = [60121, 60148, 60147]

user_change = False
group_change = False
zabbix_param = ""
hostgroup = ""
esetgroup = ""
event_ip = ""
now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

with open(sys.argv[1]) as f:
    alert = json.loads(f.read())

try:
    hostgroup = alert["agent"]["labels"]["group"]
except:
    pass

try:
    event_ip = alert["agent"]["ip"]
except:
    pass

try:
    esetgroup = alert["data"]["eset"]["group"]
except:
    pass


event_id = alert["rule"]["id"]
event_host = hostgroup + "(" +  alert["agent"]["name"] + ")"
event_description = alert["rule"]["description"]
event_target = ""
event_workstation = ""
event_member = ""
system = "windows"

if int(event_id) in exclude_events:
    sys.exit()

for x in (alert["rule"]["groups"]):
    if x == "syslog":
        system = "linux"

for x in (alert["rule"]["groups"]):
    if x == "eset":
        system = "eset"

for x in (alert["rule"]["groups"]):
    for y in usermod_events:
         if y == x:
            user_change = True

for x in (alert["rule"]["groups"]):
    for y in groupmod_events:
         if y == x:
            group_change = True

if event_description.find("S-1-5-")>=0:
     event_description = event_description[0:event_description.find("S-1-5-")]

if system == "windows":
    try:
        event_target =  alert["data"]["win"]["eventdata"]["targetUserName"]
    except:
        pass
    try:
        event_workstation = alert["data"]["win"]["eventdata"]["workstationName"]
    except:
        pass
    try:
        event_member = alert["data"]["win"]["eventdata"]["memberName"]
    except:
        pass

if system == "linux":
    try:
        event_target =  alert["data"]["dstuser"]
    except:
        pass
    try:
        event_workstation = alert["data"]["srcip"]
    except:
        pass

if system == "eset":
    try:
        event_target =  alert["data"]["eset"]["deviceName"]
    except:
        pass
    try:
        event_workstation = alert["data"]["eset"]["group"]
    except:
        pass


if user_change:
    zabbix_param = f"User modification '{event_target}' on {event_host} ({event_ip}) : {event_description}"
elif group_change:
    zabbix_param = f"Group: {event_target} , User: {event_member} on {event_host} ({event_ip}) :{event_description}"
elif int(event_id) in misp_events:
    zabbix_param = f"MISP IoC on {event_host} ({event_ip}) : {event_description}"
elif int(event_id) in failedlogin5_events:
    zabbix_param = f"Multiple failed logins {event_target} on {event_host} ({event_ip}) from {event_workstation}"
elif int(event_id) in failedlogin_events:
    zabbix_param = f"Failed login {event_target} on {event_host} from {event_workstation} : {event_description}"
elif int(event_id) in lockuser_events:
    zabbix_param = f"Locked user {event_target} on {event_host} ({event_ip}) : {event_description} : {now}"
elif int(event_id) in shutdown_events:
    zabbix_param = f"Unexpected shutdown on {event_host} ({event_ip}) : {event_description}"
elif system == "eset":
    zabbix_param = f"ESET High Level on {event_target} : {event_workstation} : {now}"
else:
    sys.exit()

if esetgroup == "SAS" or hostgroup == "SAS":
    wazuh_name = "SAS Wazuh"

sendcommand = f'zabbix_sender --tls-connect psk --tls-psk-file /etc/zabbix/psk.key --tls-psk-identity CXID2 -z {zabbix_server} -s "{wazuh_name}" -k wazuh.alert -o "{zabbix_param}"'
result = subprocess.run(sendcommand, capture_output=True, shell=True ,text=True)

with open(integration_log, 'a') as f:
    f.write(now+" : "+zabbix_param+" : "+result.stdout.replace("\n","")+"\n")
