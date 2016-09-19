import sys
import inspect
from netaddr import *
from vnc_api.vnc_api import *
from vnc_api.gen.resource_client import *
from vnc_api.gen.resource_xsd import *

def eprint(msg):
	sys.stderr.write('contrail_cli: ' + msg + '\n')	

class ContrailCli:
	def call(self, server, port, function, *args):
		self.api = VncApi(
			api_server_host = server,
			api_server_port = port)
		fun = getattr(self, function)
		fun(*args)

	def _resource_create(self, resource, obj):
		try:
			fun = getattr(self.api, resource + "_create")
			return fun(obj)
		except RefsExistError:
			pass
	def _resource_read(self, resource, fqname):
		fun = getattr(self.api, resource + "_read")
		parent = fun(fq_name_str = fqname)
		if parent is None:
			msg = "Resource %s does not exist" % (fqname)
			raise RuntimeError(msg)
		return parent

	# Commands

	def domain_create(self, name):
		obj = Domain(name)
		print self._resource_create("domain", obj)
	
	def project_create(self, name, parent_fqname):
		parent = self._resource_read("domain", parent_fqname)
		obj = Project(name, parent)
		print self._resource_create("project", obj)
	
	def network_create(self, name, project_fqname, subnet_str):
		parent = self._resource_read("project", project_fqname)
		network = VirtualNetwork(name, parent)
		ipam = self._resource_read("network_ipam", project_fqname + ":default-network-ipam")
		ipnet = IPNetwork(subnet_str)
		subnet = SubnetType(str(ipnet.ip), ipnet.prefixlen)
		ipam_subnet = IpamSubnetType(subnet)
		vn_subnet = VnSubnetsType([ipam_subnet])
		network.add_network_ipam(ipam, vn_subnet)
		print self._resource_create("virtual_network", network)

	def vm_create(self, name):
		obj = VirtualMachine(name)
		print self._resource_create("virtual_machine", obj)

	def vmi_create(self, name, parent_fqname, network_fqname):
		parent = self._resource_read("virtual_machine", parent_fqname)
		network = self._resource_read("virtual_network", network_fqname)
		obj = VirtualMachineInterface(name, parent)
		obj.add_virtual_network(network)
		print self._resource_create("virtual_machine_interface", obj)

	def instance_ip_alloc(self, name, project_fqname, network_name, subnet_str):
		addr_alloc = self._resource_read("virtual_network", project_fqname + ":addr-alloc")
		ip = self.api.virtual_network_ip_alloc(addr_alloc, subnet=subnet_str)
		network = self._resource_read("virtual_network", project_fqname + ":" + network_name)
		if len(ip) < 1:
			raise RuntimeError("IP allocation failed")
		ret = {
			'Ip': ip[0],
			'Gateway': network.get_network_ipam_refs()[0]['attr'].ipam_subnets[0].default_gateway
		}
		print json.dumps(ret, indent=4, separators=(',', ': '))

	def container_create(self, name, project_fqname, network_name, ip):
		network = self._resource_read("virtual_network", project_fqname + ":" + network_name)
		vm = VirtualMachine(name)
		vm_uuid = self._resource_create("virtual_machine", vm)
		vmi = VirtualMachineInterface(name, vm)
		vmi.add_virtual_network(network)
		vmi_uuid = self._resource_create("virtual_machine_interface", vmi)
		instance_ip = InstanceIp(name + "_" + network_name, ip)
		instance_ip.add_virtual_network(network)
		instance_ip.add_virtual_machine_interface(vmi)
		self._resource_create("instance_ip", instance_ip)
		vmi = self._resource_read("virtual_machine_interface", name + ":" + name)
		mac = vmi.virtual_machine_interface_mac_addresses.mac_address[0]
		ret = {
			'InterfaceId': vmi_uuid,
			'MachineId': vm_uuid,
			'Mac': mac
		}
		print json.dumps(ret, indent=4, separators=(',', ': '))
	
def main():
	try:
		if len(sys.argv) < 4:
			raise RuntimeError("To few arguments")
		cli = ContrailCli()
		cli.call(sys.argv[1], sys.argv[2], sys.argv[3], *sys.argv[4:])
	except Exception as e:
		eprint(str(e))
		exit(1)

if __name__ == "__main__":
	main()

