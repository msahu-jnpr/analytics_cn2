#!/usr/bin/env python
import sys
import os
import time
import json
import requests
import xml.etree.ElementTree as ET
import os
import xmltodict
from prometheus_client import start_http_server, Metric, Info, Enum, REGISTRY, Gauge
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily

class JsonCollector(object):
  def __init__(self, analytics_api_ip, control_api_ip, config_api_ip):
    self._endpoint = 'http://' + analytics_api_ip + ':8081/analytics/uves/vrouter/msahu-aio-node1.local?flat'
    self.control_api_ip = control_api_ip
    self.config_api_ip = config_api_ip

  def collect(self):
    compute_ip_list = ['10.204.220.24', '10.204.220.25', '10.204.220.61']
    for ip in compute_ip_list:
	url = "curl http://" + ip +":8085/Snh_SandeshUVECacheReq?x=VirtualMachineStats | xmllint --format - >& VirtualMachineStats.xml"
	os.system(url)
    	tree = ET.parse('VirtualMachineStats.xml')
    	root = tree.getroot()
    	for vm_stats in root.findall('./VirtualMachineStatsTrace/data/VirtualMachineStats'):
            name = vm_stats[0].text
  	    vm_stat = Metric('VMIStats', 'metrics for vm' , 'summary')
            vm_stats_prefix = 'vm_stats_'
  	    vm_stat.add_sample(vm_stats_prefix+vm_stats[1][0][0][0].tag, value=float(vm_stats[1][0][0][0].text), labels={"name": name, "host_ip": ip})
  	    vm_stat.add_sample(vm_stats_prefix+vm_stats[1][0][0][1].tag, value=float(vm_stats[1][0][0][1].text), labels={"name": name, "host_ip": ip})
  	    vm_stat.add_sample(vm_stats_prefix+vm_stats[1][0][0][3].tag, value=float(vm_stats[1][0][0][3].text), labels={"name": name, "host_ip": ip})
  	    vm_stat.add_sample(vm_stats_prefix+vm_stats[1][0][0][4].tag, value=float(vm_stats[1][0][0][4].text), labels={"name": name, "host_ip": ip})
            yield vm_stat

	url = "curl http://" + ip +":8085/Snh_SandeshUVECacheReq?x=UveVirtualNetworkAgent | xmllint --format - >& UveVirtualNetworkAgent.xml"
	os.system(url)
	with open("UveVirtualNetworkAgent.xml") as xml_file:
	    json_dict = xmltodict.parse(xml_file.read())	
	for vn in json_dict['__UveVirtualNetworkAgentTrace_list']['UveVirtualNetworkAgentTrace']:
	    name = vn['data']['UveVirtualNetworkAgent']['name']['#text']
	    vn_stats = Metric('UveVirtualNetworkAgent', 'metrics for virtual network' , 'summary')
	    vn_stats_prefix = 'vn_stats_in_stats_'
	    try:
	    	inter_vn_stats = vn['data']['UveVirtualNetworkAgent']['in_stats']['list']['UveInterVnStats']
		for stats in inter_vn_stats:
		    other_vn_name = str(stats['other_vn']['#text'])
		    tpkts = float(stats['tpkts']['#text'])
		    tpkt_bytes = float(stats['bytes']['#text'])
		    vn_stats.add_sample(vn_stats_prefix+'inter_vn_stats_tpkts', value=tpkts, labels={"name": name, "other_vn":other_vn_name, "host_ip": ip, "generator": "agent"})
		    vn_stats.add_sample(vn_stats_prefix+'inter_vn_stats_bytes', value=tpkt_bytes, labels={"name": name, "other_vn":other_vn_name, "host_ip": ip, "generator": "agent"})
	    except Exception as e:
		print("Error %s" %e)

	    try:
		in_bandwidth_usage = float(vn['data']['UveVirtualNetworkAgent']['in_bandwidth_usage']['#text']) 
		out_bandwidth_usage = float(vn['data']['UveVirtualNetworkAgent']['out_bandwidth_usage']['#text']) 
		vn_stats.add_sample(vn_stats_prefix+'in_bandwidth_usage', value=in_bandwidth_usage, labels={"name": name,"host_ip": ip, "generator": "agent"})
		vn_stats.add_sample(vn_stats_prefix+'out_bandwidth_usage', value=out_bandwidth_usage, labels={"name": name,"host_ip": ip, "generator": "agent"})
	    except Exception as e:
		print("Error %s" %e)
	    #import pdb;pdb.set_trace();

	    try:
	    	policy_rule_stats_list = vn['data']['UveVirtualNetworkAgent']['policy_rule_stats']['list']['NetworkPolicyRuleStats']
	    	for rule in policy_rule_stats_list:
		    rule_name = rule['rule']['#text']
		    rule_count = int(rule['count']['#text'])
		    vn_stats.add_sample(vn_stats_prefix+'policy_rule_stats', value=rule_count, labels={"name": name, "generator": "agent", "rule_name":rule_name})
	    except Exception as e:
		    print("Error %s" %e)
	
 	    vn_stats_prefix = 'vn_stats_'
	    try:
		inter_vn_stats = vn['data']['UveVirtualNetworkAgent']['vn_stats']['list']['InterVnStats']
		for stats in inter_vn_stats:
		    other_vn_name = str(stats['other_vn']['#text'])
		    vrouter = str(stats['vrouter']['#text'])
		    in_tpkts = int(stats['in_tpkts']['#text'])
		    in_bytes = int(stats['in_bytes']['#text'])
		    out_tpkts = int(stats['out_tpkts']['#text'])
		    out_bytes = int(stats['out_bytes']['#text'])
		    vn_stats.add_sample(vn_stats_prefix+'inter_vn_stats_in_tpkts', value=in_tpkts, labels={"name": name, "other_vn":other_vn_name, "host_ip": ip, "generator": "agent", "vrouter":vrouter})
		    vn_stats.add_sample(vn_stats_prefix+'inter_vn_stats_out_tpkts', value=out_tpkts, labels={"name": name, "other_vn":other_vn_name, "host_ip": ip, "generator": "agent", "vrouter":vrouter})
		    vn_stats.add_sample(vn_stats_prefix+'inter_vn_stats_in_bytes', value=in_bytes, labels={"name": name, "other_vn":other_vn_name, "host_ip": ip, "generator": "agent", "vrouter":vrouter})
		    vn_stats.add_sample(vn_stats_prefix+'inter_vn_stats_out_bytes', value=out_bytes, labels={"name": name, "other_vn":other_vn_name, "host_ip": ip, "generator": "agent", "vrouter":vrouter})
	    except Exception as e:
		print("Error %s" %e)
	    yield vn_stats
		
		
		

    uve_vrouter = Metric('uve_vrouter', 'metrics for vrouter' , 'summary')
    uve_vrouter.add_sample('uve_vrouter_contrail_config', value=1, labels={"virtual_router_ip_address":"10.204.88.234"})
    uve_vrouter.add_sample('uve_vrouter_agent', value=1, labels={"control_ip": "10.204.88.234"})
    yield uve_vrouter
    
    yield GaugeMetricFamily('node_status_disk_usage_info_percentage_partition_space_used', 'Disk usage', value=95)

    yield GaugeMetricFamily('my_gauge', 'Help text', value=7)
    c = CounterMetricFamily('my_counter_total', 'Help text', labels=['foo'])
    c.add_metric(['bar'], 1.7)
    c.add_metric(['baz'], 3.8)
    yield c

    process_info = Metric('ProcessInfo', 'metric for processes', 'summary')
    process_info.add_sample('process_info:start_count', value=4, labels={"name": "contrail-vrouter-agent", "process_state": "running"})
    process_info.add_sample('process_info_stop_count', value=0, labels={"name": "contrail-vrouter-agent", "process_state": "running"})
    process_info.add_sample('process_info_exit_count', value=3, labels={"name": "contrail-vrouter-agent", "process_state": "running"})
    process_info.add_sample('process_info_start_count', value=4, labels={"name": "contrail-vrouter-nodemgr", "process_state": "running"})
    process_info.add_sample('process_info_stop_count', value=0, labels={"name": "contrail-vrouter-nodemgr", "process_state": "running"})
    process_info.add_sample('process_info_exit_count', value=3, labels={"name": "contrail-vrouter-nodemgr", "process_state": "running"})
    process_info.add_sample('process_info_start_count', value=4, labels={"name": "contrail-vrouter-agent", "process_state": "running"})

    process_info.add_sample('process_info_status_running', value=1, labels={"name": "contrail-vrouter-agent"})
    process_info.add_sample('process_info_status_running', value=1, labels={"name": "contrail-analytics-api"})
    process_info.add_sample('process_info_status_running', value=1, labels={"name": "contrail-collector"})
    process_info.add_sample('process_info_status_running', value=0, labels={"name": "contrail-analytics-nodemgr"})
    process_info.add_sample('process_info_status_running', value=0, labels={"name": "contrail-vrouter-nodemgr"})
    yield process_info

    process_status = Metric('ProcessStatus', 'metric for processes status', 'summary')
    process_status.add_sample('process_status_up', value=1, labels={"module_id": "contrail-vrouter-agent", "instance_id": "0", "state": "Functional", "server_addrs": "10.204.88.234:8086", "type": "Collector",
			"name": "Collector"})
    yield process_status

    '''
    i = Info('my_build_version', 'Description of info')
    i.info({'version': '1.2.3', 'buildhost': 'foo@bar'})
    yield i
    e = Enum('my_task_state', 'Description of enum', states=['starting', 'running', 'stopped'])
    e.state('running')
    yield e
    '''
    ##
    # get metrics for vrouters from analytics:
    ##
    url = self._endpoint

    # Fetch the JSON
    response = json.loads(requests.get(url).content.decode('UTF-8'))
    #print (response)
   
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

    # VrouterAgent
    if response['VrouterAgent']['res_limit'] == 'True':
	uve_vrouter_metric.add_sample('vrouter_agent_res_limit', value=1, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    else:
        uve_vrouter_metric.add_sample('vrouter_agent_res_limit', value=0, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})

    if response['VrouterAgent']['res_table_limit'] == 'True':
	uve_vrouter_metric.add_sample('vrouter_agent_res_table_limit', value=1, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    else:
        uve_vrouter_metric.add_sample('vrouter_agent_res_table_limit', value=0, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    #import pdb; pdb.set_trace()
    uve_vrouter_metric.add_sample('test1', value=100, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local', 'test_label':'test_value'})
    uve_vrouter_metric.add_sample('test2', value=100, labels={'uve':'vrouter', 'instance':'msahu-aio-node1.local'})
    yield uve_vrouter_metric
  
    metric = Metric('tungstenfabric_metrics',
        'metrics for tungsten fabric', 'summary')

     
    # vRouter UVE
    """
    for entry in response['value']:
      name = entry["name"]
      tmp = entry["value"]["VrouterStatsAgent"]

      drop_stats = tmp["raw_drop_stats"]
      for k in drop_stats:
        metric.add_sample('drop_stats_'+k, value=drop_stats[k], labels={"host_id": name})
 
      flow_rate = tmp["flow_rate"]
      for k in flow_rate:
        metric.add_sample('flow_rate_'+k, value=flow_rate[k], labels={"host_id": name})

      phy_if_stats = tmp["raw_phy_if_stats"]
      phy_if_stats = phy_if_stats.values()[0]
      for k in phy_if_stats:
        metric.add_sample('phy_if_stats_'+k, value=phy_if_stats[k], labels={"host_id": name})

      tmp = entry["value"]["VrouterControlStats"]
      rt_table_size = tmp["raw_rt_table_size"]
      num_of_rt=0
      num_of_routes=0
      for k in rt_table_size:
        num_of_rt+=1
        for kk in rt_table_size[k]:
          num_of_routes+=rt_table_size[k][kk]
      metric.add_sample('num_of_route_tables', value=num_of_rt, labels={"host_id": name})
      metric.add_sample('num_of_routes', value=num_of_routes, labels={"host_id": name})

    # control introspect
    num_of_vns=os.popen ("python ist.py ctr route summary -f text | grep -w name | wc -l").read()
    metric.add_sample('num_of_route_tables', value=num_of_vns, labels={"host_id": self.control_api_ip})
    num_of_routes=os.popen ("python ist.py ctr route summary -f text | grep -w prefixes | awk -F: '{sum+=$2}; END{print sum}'").read()
    metric.add_sample('num_of_routes', value=num_of_routes, labels={"host_id": self.control_api_ip})
    num_of_routing_instances=os.popen ("python ist.py ctr ri -f text | grep '^  name' | wc -l").read()
    metric.add_sample('num_of_routing_instances', value=num_of_routing_instances, labels={"host_id": self.control_api_ip})
    num_of_bgp_blocks=os.popen ("python ist.py ctr bgp_stats | grep -w blocked_count | awk -F: '{sum+=$2}; END{print sum}'").read()
    metric.add_sample('num_of_bgp_blocks', value=num_of_bgp_blocks, labels={"host_id": self.control_api_ip})
    num_of_bgp_calls=os.popen ("python ist.py ctr bgp_stats | grep -w calls | awk -F: '{sum+=$2}; END{print sum}'").read()
    metric.add_sample('num_of_bgp_calls', value=num_of_bgp_calls, labels={"host_id": self.control_api_ip})
    num_of_xmpp_blocks=os.popen ("python ist.py ctr xmpp stats -f text | grep -w blocked_count | awk -F: '{sum+=$2}; END{print sum}'").read()
    metric.add_sample('num_of_xmpp_blocks', value=num_of_xmpp_blocks, labels={"host_id": self.control_api_ip})
    num_of_xmpp_calls=os.popen ("python ist.py ctr xmpp stats -f text | grep -w calls | awk -F: '{sum+=$2}; END{print sum}'").read()
    metric.add_sample('num_of_xmpp_calls', value=num_of_xmpp_calls, labels={"host_id": self.control_api_ip})

    # configdb
    config_api_url = 'http://' + self.config_api_ip + ':8082/'

    response = json.loads(requests.get(config_api_url + 'virtual-networks').content.decode('UTF-8'))
    num_of_virtual_networks = len(response['virtual-networks'])
    metric.add_sample('num_of_virtual_networks', value=num_of_virtual_networks, labels={"host_id": self.config_api_ip})

    response = json.loads(requests.get(config_api_url + 'logical-routers').content.decode('UTF-8'))
    num_of_logical_routers = len(response['logical-routers'])
    metric.add_sample('num_of_logical_routers', value=num_of_logical_routers, labels={"host_id": self.config_api_ip})

    response = json.loads(requests.get(config_api_url + 'projects').content.decode('UTF-8'))
    num_of_projects = len(response['projects'])
    metric.add_sample('num_of_projects', value=num_of_projects, labels={"host_id": self.config_api_ip})

    response = json.loads(requests.get(config_api_url + 'virtual-machine-interfaces').content.decode('UTF-8'))
    num_of_virtual_machine_interfaces = len(response['virtual-machine-interfaces'])
    metric.add_sample('num_of_virtual_machine_interfaces', value=num_of_virtual_machine_interfaces, labels={"host_id": self.config_api_ip})
    #metric.add_sample('num_of_test_vm', value=num_of_virtual_machine_interfaces, labels={"host_id": self.config_api_ip})
    metric.add_sample('num_of_test_vm', value=10, labels={"host_id": self.config_api_ip})

    yield metric
    #e = Enum('my_task_state', 'Description of enum',
    #    states=['starting', 'running', 'stopped'])
    #e.state('running')
    #yield e
    """


if __name__ == '__main__':
  # Usage: tf-analytics-exporter.py
  http_port=11234
  start_http_server(int(http_port))
  analytics_api_ip=os.popen("netstat -ntlp | grep -w 8081 | awk '{print $4}' | awk -F: '{print $1}'").read().rstrip()
  control_api_ip=analytics_api_ip ## temporary
  config_api_ip=analytics_api_ip ## temporary
  #print(analytics_api_ip)
  REGISTRY.register(JsonCollector(analytics_api_ip, control_api_ip, config_api_ip))

  while True: time.sleep(1)

