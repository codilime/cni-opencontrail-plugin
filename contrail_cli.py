import sys
import inspect
from netaddr import *
from vnc_api.vnc_api import *
from vnc_api.gen.resource_client import *
from vnc_api.gen.resource_xsd import *
from contrail_vrouter_api.vrouter_api import *

def eprint(msg):
    sys.stderr.write('contrail_cli: ' + msg + '\n')	

def fqname(*args):
    ret = []
    for name in args:
        ret += split(":")
    return ret

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
            return self._resource_read(resource, fqname=obj.fq_name).uuid

    def _resource_read(self, resource, fqname=None, fqname_str=None, id=None):
        fun = getattr(self.api, resource + "_read")
        obj = fun(fq_name=fqname, fq_name_str=fqname_str, id=id)
        if obj is None:
            msg = "Resource does not exist"
            raise RuntimeError(msg)
        return obj)

    # Commands

    def control_domain_create(self, name):
        obj = Domain(name)
        uuid = self._resource_create("domain", obj)
        ret = {
            'uuid': uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
	
    def control_project_create(self, name, parent_fqname):
        parent = self._resource_read("domain", fqname_str=parent_fqname)
        obj = Project(name, parent)
        uuid = self._resource_create("project", obj)
        ret = {
            'uuid': uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
	
    def control_network_create(self, name, project_fqname, subnet_str):
        parent = self._resource_read("project", fqname_str=project_fqname)
        ipam = self._resource_read("network_ipam", fqname=fqname(project_fqname, "default-network-ipam"))
        policy = self._resource_read("network_policy", fqname=fqname(project_fqname, "default-network-policy"))
        network = None
        try:
            uuid = self.api.fq_name_to_id("virtual_network", fqname(project_fqname, name))
            network = self.api.virtual_network_read(id=uuid)
        except NoIdError:
            network = VirtualNetwork(name, parent)
            uuid = self._resource_create("virtual_network", network)
            network = self._resource_read("virtual_network", id=uuid)

        ipnet = IPNetwork(subnet_str)
        subnet = SubnetType(str(ipnet.ip), ipnet.prefixlen)
        ipam_subnet = IpamSubnetType(subnet)
        
        ipam_list = network.get_network_ipam_refs()
        ipam_subnet_list = None
        if (ipam_list is None or
                len(ipam_list) == 0 or
                ipam_list[0] is None or
                ipam_list[0]['attr'] is None or
                ipam_list[0]['attr'].ipam_subnets is None):
            ipam_subnet_list = []
        elif ipam_list:
            ipam_subnet_list = ipam_list[0]['attr'].ipam_subnets
        subnet_found = False
        for s in ipam_subnet_list:
            if s.subnet == ipam_subnet.subnet:
                subnet_found = True
                break
        if subnet_found == False:
            ipam_subnet_list.append(ipam_subnet)
        network.set_network_ipam(ipam, VnSubnetsType(ipam_subnet_list))
        network.set_network_policy(policy, VirtualNetworkPolicyType())
        self.api.virtual_network_update(network)
        ret = {
            'uuid': network.uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_floating_ip_create(self, name, project_fqname, network_name, subnet_str, ip, vmi_uuid):
        parent = self._resource_read("virtual_network", fqname=fqname(project_fqname, network_name))
        project = self._resource_read("project", fqname_str=project_fqname)
        vmi = self._resource_read("virtual_machine_interface", id=vmi_uuid)
        ipnet = IPNetwork(subnet_str)
        subnet = SubnetType(str(ipnet.ip), ipnet.prefixlen)
        pool_type = FloatingIpPoolType([subnet])
        pool = FloatingIpPool(network_name, parent, pool_type)
        pool_uuid = self._resource_create("floating_ip_pool", pool)
        fip = FloatingIp(name, pool, ip)
        fip.add_project(project)
        fip.add_virtual_machine_interface(vmi)
        uuid = self._resource_create("floating_ip", fip)
        ret = {
            'floating_ip_uuid': uuid,
            'floating_ip_pool_uuid': pool_uuid
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_floating_ip_delete(self, name, project_fqname, network_name):
        fip = self.api.floating_ip_read(fq_name=fqname(project_fqname, network_name, network_name, name))
        self.api.floating_ip_delete(id=fip.uuid)
        ret = {
            'ip': fip.floating_ip_address,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_instance_ip_alloc(self, project_fqname, network_name, subnet_str):
        network = self._resource_read("virtual_network", fqname=fqname(project_fqname, network_name))
        ip = self.api.virtual_network_ip_alloc(network, subnet=subnet_str)
        if len(ip) != 1:
            raise RuntimeError("IP allocation failed (%d addresses allocated, 1 expected)" % len(ip))
        ret = {
            'ip': ip[0],
            'gateway': network.get_network_ipam_refs()[0]['attr'].ipam_subnets[0].default_gateway
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_instance_ip_free(self, project_fqname, network_name, subnet_str, ip):
        network = self._resource_read("virtual_network", fqname=fqname(project_fqname, network_name))
        result = self.api.virtual_network_ip_free(network, [ip], subnet=subnet_str)
        ret = {
            'result': result,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_container_create(self, name, project_fqname, network_name):
        project = self._resource_read("project", fqname_str=project_fqname)
        vm = VirtualMachine(name)
        vm_uuid = self._resource_create("virtual_machine", vm)
        vmi = VirtualMachineInterface(name, project)
        network = self._resource_read("virtual_network", fqname=fqname(project_fqname, network_name))
        vmi.add_virtual_network(network)
        vmi.add_virtual_machine(vm)
        vmi_uuid = self._resource_create("virtual_machine_interface", vmi)
        vmi = self._resource_read("virtual_machine_interface", fqname=fqname(project_fqname, name))
        ret = {
            'vmi_uuid': vmi_uuid,
            'vm_uuid': vm_uuid,
            'mac': vmi.virtual_machine_interface_mac_addresses.mac_address[0]
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
    
    def control_container_delete(self, name, project_fqname):
        vmi = self.api.virtual_machine_interface_read(fq_name=fqname(project_fqname, name))
        vm = self.api.virtual_machine_read(fq_name=[name])
        self.api.virtual_machine_interface_delete(id=vmi.uuid)
        self.api.virtual_machine_delete(id=vm.uuid)
        ret = {
            'vmi_uuid': vmi.uuid,
            'vm_uuid': vm.uuid,
            'mac': vmi.virtual_machine_interface_mac_addresses.mac_address[0]
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_instance_ip_create(self, name, ip, network_uuid, vmi_uuid):
        instance_ip = InstanceIp(name, ip)
        network = self._resource_read("virtual_network", id=network_uuid)
        instance_ip.add_virtual_network(network)
        vmi = self._resource_read("virtual_machine_interface", id=vmi_uuid)
        instance_ip.add_virtual_machine_interface(vmi)
        uuid = self._resource_create("instance_ip", instance_ip)
        ret = {
            'uuid': uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_instance_ip_delete(self, name):
        ip = self.api.instance_ip_read(fq_name=[name])
        self.api.instance_ip_delete(id=ip.uuid)
        ret = {
            'ip': ip.instance_ip_address,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
    
    def vrouter_port_add(self, name, project_uuid, vn_uuid, vm_uuid, vif_uuid, iface_name, mac, ip):
        result = self.api.add_port(
                vm_uuid,
                vif_uuid,
                iface_name,
                mac,
                ip_address=ip,
                vn_id=vn_uuid,
                display_name=name,
                hostname=name,
                vm_project_id=project_uuid,
                port_type='NovaVMPort')
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

