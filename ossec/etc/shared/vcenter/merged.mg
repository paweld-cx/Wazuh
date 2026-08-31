#vcenter
!228 ar.conf
restart-ossec0 - restart-ossec.sh - 0
restart-ossec0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-ossec.sh - 0
restart-wazuh0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-wazuh - 0
restart-wazuh0 - restart-wazuh.exe - 0
!259 agent.conf
  <agent_config>
    <labels>
      <label key="app">vcenter</label>
    </labels>
    <client_buffer>
      <disabled>no</disabled>
      <queue_size>30000</queue_size>
      <events_per_second>1000</events_per_second>
    </client_buffer>
  </agent_config>
