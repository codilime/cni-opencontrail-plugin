import sys
import inspect
from netaddr import *
from vnc_api.vnc_api import *
from vnc_api.gen.resource_client import *
from vnc_api.gen.resource_xsd import *
from contrail_vrouter_api.vrouter_api import *

def eprint(msg):
    sys.stderr.write('contrail_cli: ' + msg + '\n')	

class ContrailCli:

    def control_call(self, args):
        if len(args) < 3:
            raise RuntimeError("Too few arguments")
        self.api = VncApi(
            api_server_host = args[0],
            api_server_port = args[1])
        self._call('control_' + args[2], *args[3:])
    
    def vrouter_call(self, args):
        if len(args) < 2:
            raise RuntimeError("Too few arguments")
        self.api = ContrailVRouterApi(server_port=int(args[0]))
        self._call('vrouter_' + args[1], *args[2:])
    
    def _call(self, function, *args):
        fun = getattr(self, function)
        fun(*args)

    def _resource_create(self, resource, obj):
        try:
            fun = getattr(self.api, resource + "_create")
            return fun(obj)
        except RefsExistError:
            pass

    def _resource_read(self, resource, fqname=None, fqname_str=None):
        fun = getattr(self.api, resource + "_read")
        obj = fun(fq_name=fqname, fq_name_str = fqname_str)
        if obj is None:
            msg = "Resource %s does not exist" % (fqname)
            raise RuntimeError(msg)
        return obj

    # Commands

    def control_domain_create(self, name):
        obj = Domain(name)
        print self._resource_create("domain", obj)
	
    def control_project_create(self, name, parent_fqname):
        parent = self._resource_read("domain", fqname_str=parent_fqname)
        obj = Project(name, parent)
        print self._resource_create("project", obj)
	
    def control_network_create(self, name, project_fqname, subnet_str):
        parent = self._resource_read("project", fqname_str=project_fqname)
        network = VirtualNetwork(name, parent)
        ipam = self._resource_read("network_ipam", fqname_str=project_fqname + ":default-network-ipam")
        ipnet = IPNetwork(subnet_str)
        subnet = SubnetType(str(ipnet.ip), ipnet.prefixlen)
        ipam_subnet = IpamSubnetType(subnet)
        vn_subnet = VnSubnetsType([ipam_subnet])
        network.add_network_ipam(ipam, vn_subnet)
        print self._resource_create("virtual_network", network)

    def control_vm_create(self, name):
        obj = VirtualMachine(name)
        print self._resource_create("virtual_machine", obj)

    def control_vmi_create(self, name, parent_fqname, network_fqname):
        parent = self._resource_read("virtual_machine", fqname_str=parent_fqname)
        network = self._resource_read("virtual_network", fqname_str=network_fqname)
        obj = VirtualMachineInterface(name, parent)
        obj.add_virtual_network(network)
        print self._resource_create("virtual_machine_interface", obj)

    def control_instance_ip_alloc(self, project_fqname, network_name, subnet_str):
        addr_alloc = self._resource_read("virtual_network", fqname_str=project_fqname + ":addr-alloc")
        ip = self.api.virtual_network_ip_alloc(addr_alloc, subnet=subnet_str)
        network = self._resource_read("virtual_network", fqname_str=project_fqname + ":" + network_name)
        if len(ip) < 1:
            raise RuntimeError("IP allocation failed")
        ret = {
            'Ip': ip[0],
            'Gateway': network.get_network_ipam_refs()[0]['attr'].ipam_subnets[0].default_gateway
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_instance_ip_free(self, project_fqname, network_name, subnet_str, ip):
        addr_alloc = self._resource_read("virtual_network", fqname_str=project_fqname + ":addr-alloc")
        result = self.api.virtual_network_ip_free(addr_alloc, [ip], subnet=subnet_str)
        print result

    def control_container_create(self, name, project_fqname, network_name, ip):
        network = self._resource_read("virtual_network", fqname_str=project_fqname + ":" + network_name)
        vm = VirtualMachine(name)
        vm_uuid = self._resource_create("virtual_machine", vm)
        vmi = VirtualMachineInterface(name, vm)
        vmi.add_virtual_network(network)
        vmi_uuid = self._resource_create("virtual_machine_interface", vmi)
        instance_ip = InstanceIp(name + "_" + network_name, ip)
        instance_ip.add_virtual_network(network)
        instance_ip.add_virtual_machine_interface(vmi)
        self._resource_create("instance_ip", instance_ip)
        vmi = self._resource_read("virtual_machine_interface", fqname=[name, name])
        mac = vmi.virtual_machine_interface_mac_addresses.mac_address[0]
        ret = {
            'InterfaceId': vmi_uuid,
            'MachineId': vm_uuid,
            'Mac': mac
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
    
    def control_container_delete(self, name, project_fqname, network_name):
        instance_ip = self.api.instance_ip_read(fq_name=[name + "_" + network_name])
        vmi = self.api.virtual_machine_interface_read(fq_name=[name, name])
        self.api.instance_ip_delete(fq_name=[name + "_" + network_name])
        self.api.virtual_machine_interface_delete([name, name])
        self.api.virtual_machine_delete([name])
        ret = {
            'InterfaceId': vmi.uuid,
            'IP': instance_ip.instance_ip_address,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
    
    def vrouter_port_add(self, name, vm_uuid, vif_uuid, network_uuid, iface_name, mac):
        result = self.api.add_port(
                vm_uuid,
                vif_uuid,
                iface_name,
                mac,
                port_type='NovaVMPort',
                display_name=name)
        if result != True:
            raise RuntimeError("Operation failed. Probably vrouter is not running.")
    
    def vrouter_port_del(self, vif_uuid):
        self.api.delete_port(vif_uuid)
	
def main():
    try:
        if len(sys.argv) < 2:
            raise RuntimeError("Too few arguments")
        cli = ContrailCli()
        if sys.argv[1] == "control":
            cli.control_call(sys.argv[2:])
        if sys.argv[1] == "vrouter":
            cli.vrouter_call(sys.argv[2:])
    except Exception as e:
        eprint(str(e))
        exit(1)

if __name__ == "__main__":
	main()

