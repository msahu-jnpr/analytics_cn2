#!/usr/bin/env python
import sys
import os
import time
import json
import requests
import xml.etree.ElementTree as ET
import os
from prometheus_client import start_http_server, Metric, Info, Enum, REGISTRY, Gauge
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily

class JsonCollector(object):
  def __init__(self, analytics_api_ip, control_api_ip, config_api_ip):
    self._endpoint = 'http://' + analytics_api_ip + ':8081/analytics/uves/vrouter/msahu-aio-node1.local?flat'
    self.control_api_ip = control_api_ip
    self.config_api_ip = config_api_ip

  def collect(self):
    url = self._endpoint

    # Fetch the JSON
    response = json.loads(requests.get(url).content.decode('UTF-8'))
   
    # vrouter uve
    # ComputeCpuState 
    uve_vrouter_metric = Metric('uve_vrouter_metric', 'Vrouter uve metrics', 'summary')
    uve_vrouter_metric.add_sample('vrouter_compute_cpu_state_cpu_info_mem_res', value=response['ComputeCpuState']['cpu_info'][0]['mem_res'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_compute_cpu_state_cpu_info_mem_virt', value=response['ComputeCpuState']['cpu_info'][0]['mem_virt'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_compute_cpu_state_cpu_info_cpu_share', value=response['ComputeCpuState']['cpu_info'][0]['cpu_share'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_compute_cpu_state_cpu_info_used_sys_mem', value=response['ComputeCpuState']['cpu_info'][0]['used_sys_mem'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_compute_cpu_state_cpu_info_one_min_cpuload', value=response['ComputeCpuState']['cpu_info'][0]['one_min_cpuload'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    # NodeStatus
    uve_vrouter_metric.add_sample('vrouter_node_status_build_info', value=1,
			labels={"build_info": response['NodeStatus']['build_info'], 'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_node_status_installed_package_version', value=1,
			labels={"installed_package_version": response['NodeStatus']['installed_package_version'], 'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_node_status_running_package_version', value=1,
			labels={"installed_package_version": response['NodeStatus']['running_package_version'], 'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_node_status_disk_usage_info_partition_space_available_1k', value=response['NodeStatus']['disk_usage_info']['/dev/mapper/centos_centos7-root']['partition_space_available_1k'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local', 'partition_type': "xfs"})
    uve_vrouter_metric.add_sample('vrouter_node_status_disk_usage_info_partition_space_used_1k', value=response['NodeStatus']['disk_usage_info']['/dev/mapper/centos_centos7-root']['partition_space_used_1k'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local', 'partition_type': "xfs"})
    uve_vrouter_metric.add_sample('vrouter_node_status_disk_usage_info_percentage_partition_space_used', value=response['NodeStatus']['disk_usage_info']['/dev/mapper/centos_centos7-root']['percentage_partition_space_used'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local', 'partition_type': "xfs"})

    # NodeStatus -> process_mem_cpu_usage
    uve_vrouter_metric.add_sample('vrouter_node_status_process_mem_cpu_usage_mem_res', value=response['NodeStatus']['process_mem_cpu_usage']['contrail-vrouter-agent']['mem_res'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','type': 'contrail-vrouter-agent'})
    uve_vrouter_metric.add_sample('vrouter_node_status_process_mem_cpu_usage_mem_virt', value=response['NodeStatus']['process_mem_cpu_usage']['contrail-vrouter-agent']['mem_virt'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','type': 'contrail-vrouter-agent'})
    uve_vrouter_metric.add_sample('vrouter_node_status_process_mem_cpu_usage_cpu_share', value=response['NodeStatus']['process_mem_cpu_usage']['contrail-vrouter-agent']['cpu_share'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','type': 'contrail-vrouter-agent'})
    uve_vrouter_metric.add_sample('vrouter_node_status_process_mem_cpu_usage_mem_res', value=response['NodeStatus']['process_mem_cpu_usage']['contrail-vrouter-nodemgr']['mem_res'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','type': 'contrail-vrouter-nodemgr'})
    uve_vrouter_metric.add_sample('vrouter_node_status_process_mem_cpu_usage_mem_virt', value=response['NodeStatus']['process_mem_cpu_usage']['contrail-vrouter-nodemgr']['mem_virt'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','type': 'contrail-vrouter-nodemgr'})
    uve_vrouter_metric.add_sample('vrouter_node_status_process_mem_cpu_usage_cpu_share', value=response['NodeStatus']['process_mem_cpu_usage']['contrail-vrouter-nodemgr']['cpu_share'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','type': 'contrail-vrouter-nodemgr'})

    # NodeStatus -> system_cpu_usage
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_usage_fifteen_min_avg', value=response['NodeStatus']['system_cpu_usage']['fifteen_min_avg'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_usage_cpu_share', value=response['NodeStatus']['system_cpu_usage']['cpu_share'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_usage_five_min_avg', value=response['NodeStatus']['system_cpu_usage']['five_min_avg'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_usage_one_min_avg', value=response['NodeStatus']['system_cpu_usage']['one_min_avg'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})

    # NodeStatus -> system_mem_usage
    uve_vrouter_metric.add_sample('vrouter_node_status_system_mem_usage_used', value=response['NodeStatus']['system_mem_usage']['used'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_mem_usage_cached', value=response['NodeStatus']['system_mem_usage']['cached'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_mem_usage_free', value=response['NodeStatus']['system_mem_usage']['free'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_mem_usage_total', value=response['NodeStatus']['system_mem_usage']['total'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local','node_type': "vrouter"})

    # NodeStatus -> system_cpu_info
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_info_num_core_per_socket', value=response['NodeStatus']['system_cpu_info']['num_core_per_socket'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_info_num_thread_per_core', value=response['NodeStatus']['system_cpu_info']['num_thread_per_core'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_info_num_cpu', value=response['NodeStatus']['system_cpu_info']['num_cpu'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    uve_vrouter_metric.add_sample('vrouter_node_status_system_cpu_info_num_socket', value=response['NodeStatus']['system_cpu_info']['num_socket'],
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})

    # NodeStatus -> process_info
    for i in range(len(response['NodeStatus']['process_info'])):
	if response['NodeStatus']['process_info'][i]['process_state'] == 'PROCESS_STATE_RUNNING':
	    val = 1
	else:
	    val = 0
	uve_vrouter_metric.add_sample('vrouter_node_status_process_running', value = val,
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local', 'process_name': response['NodeStatus']['process_info'][i]['process_name']})

    # VrouterStatsAgent -> raw_vhost_stats
    for key in response['VrouterStatsAgent']['raw_vhost_stats'].keys():
	if key != 'name':
	    uve_vrouter_metric.add_sample('vrouter_stats_agent_raw_vhost_stats_'+key, value=float(response['VrouterStatsAgent']['raw_vhost_stats'][key]),
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local', 'name': response['VrouterStatsAgent']['raw_vhost_stats']['name']})

    # VrouterStatsAgent -> flow_rate 
    for key in response['VrouterStatsAgent']['flow_rate'].keys():
	if key != 'name':
	    uve_vrouter_metric.add_sample('vrouter_stats_agent_flow_rate_'+key, value=float(response['VrouterStatsAgent']['flow_rate'][key]),
			labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})

    # VrouterAgent -> res_limit and res_table_limit
    if response['VrouterAgent']['res_limit'] == 'True':
	uve_vrouter_metric.add_sample('vrouter_agent_res_limit', value=1, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    else:
        uve_vrouter_metric.add_sample('vrouter_agent_res_limit', value=0, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})

    if response['VrouterAgent']['res_table_limit'] == 'True':
	uve_vrouter_metric.add_sample('vrouter_agent_res_table_limit', value=1, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    else:
        uve_vrouter_metric.add_sample('vrouter_agent_res_table_limit', value=0, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    yield uve_vrouter_metric
     

if __name__ == '__main__':
  http_port=11234
  start_http_server(int(http_port))
  analytics_api_ip=os.popen("netstat -ntlp | grep -w 8081 | awk '{print $4}' | awk -F: '{print $1}'").read().rstrip()
  REGISTRY.register(JsonCollector(analytics_api_ip)

  while True: time.sleep(1)

