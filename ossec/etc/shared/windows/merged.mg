#windows
!228 ar.conf
restart-ossec0 - restart-ossec.sh - 0
restart-ossec0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-ossec.sh - 0
restart-wazuh0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-wazuh - 0
restart-wazuh0 - restart-wazuh.exe - 0
!1495 agent.conf
  <agent_config>
    <localfile>
      <location>Microsoft-Windows-Sysmon/Operational</location>
      <log_format>eventchannel</log_format>
      <only-future-events>no</only-future-events>
    </localfile>
    <localfile>
      <location>System</location>
      <log_format>eventchannel</log_format>
      <only-future-events>no</only-future-events>
    </localfile>
    <localfile>
      <location>Security</location>
      <log_format>eventchannel</log_format>
      <only-future-events>no</only-future-events>
    </localfile>
    <localfile>
      <location>Microsoft-Windows-PowerShell/Operational</location>
      <log_format>eventchannel</log_format>
      <only-future-events>no</only-future-events>
    </localfile>
    <localfile>
      <location>Microsoft-Windows-Windows Defender/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>
    <syscheck>
      <directories>C:\Users\Public</directories>
      <directories realtime="yes">C:\Users\*\Downloads</directories>
      <directories realtime="yes">C:\Users\*\Documents</directories>
      <directories realtime="yes">C:\Users\*\Desktop</directories>
      <directories realtime="yes">C:\Users\Public</directories>
      <directories realtime="yes">C:\Users\*\AppData\Local\Temp</directories>
      <directories realtime="yes">%WINDIR%\Temp</directories>
      <directories>C:\Temp</directories>
    </syscheck>
    <labels>
      <label key="system">windows</label>
    </labels>
  </agent_config>
