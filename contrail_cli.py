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
        ret += name.split(":")
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

    def _object_create(self, resource, obj):
        try:
            fun = getattr(self.api, resource + "_create")
            return fun(obj)
        except RefsExistError:
            return self.api.fq_name_to_id(resource, obj.fq_name)

    def _object_delete(self, resource, obj):
        fun = getattr(self.api, resource + "_delete")
        fun(id=obj.uuid)

    def _object_read(self, resource, fqname=None, fqname_str=None, id=None):
        fun = getattr(self.api, resource + "_read")
        obj = fun(fq_name=fqname, fq_name_str=fqname_str, id=id)
        if obj is None:
            if fqname != None:
                raise NoIdError("Error: Object %s not found.", ', '.join(fqname))
            elif fqname_str != None:
                raise NoIdError("Error: Object %s not found.", fqname_str)
            elif id != None:
                raise NoIdError("Error: Object %s not found.", id)
            else:
                raise NoIdError("Error: Object not found.")
        return obj

    def _object_try_read(self, resource, fqname=None, fqname_str=None, id=None):
        try:
            return self._object_read(resource, fqname, fqname_str, id)
        except NoIdError:
            return None

    # Commands

    def control_domain_create(self, name):
        obj = Domain(name)
        uuid = self._object_create("domain", obj)
        ret = {
            'uuid': uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
	
    def control_project_create(self, name, parent_fqname):
        parent = self._object_read("domain", fqname_str=parent_fqname)
        obj = Project(name, parent)
        uuid = self._object_create("project", obj)
        ret = {
            'uuid': uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))
	
    def control_network_create(self, name, project_fqname, subnet_str):
        parent = self._object_read("project", fqname_str=project_fqname)
        ipam = self._object_read("network_ipam", fqname=fqname(project_fqname, "default-network-ipam"))
        network = self._object_try_read("virtual_network", fqname=fqname(project_fqname, name))
        if network is None:
            network = VirtualNetwork(name, parent)
            uuid = self._object_create("virtual_network", network)
            network = self._object_read("virtual_network", id=uuid)

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
        self.api.virtual_network_update(network)
        ret = {
            'uuid': network.uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_floating_ip_create(self, name, project_fqname, network_name, subnet_str):
        network = self._object_read("virtual_network", fqname=fqname(project_fqname, network_name))
        ipnet = IPNetwork(subnet_str)
        subnet = SubnetType(str(ipnet.ip), ipnet.prefixlen)
        pool = self._object_try_read("floating_ip_pool", fqname=network.fq_name + [network_name])
        if pool is None:
            pool_type = FloatingIpPoolType([subnet])
            pool = FloatingIpPool(network_name, network, pool_type)
            pool.uuid = self._object_create("floating_ip_pool", pool)
        fip = self._object_try_read("floating_ip", fqname=pool.fq_name + [name])
        if fip is None:
            fip = FloatingIp(name, pool)
            project = self._object_read("project", fqname_str=project_fqname)
            fip.add_project(project)
            fip.uuid = self._object_create("floating_ip", fip)
        fip = self._object_read("floating_ip", id=fip.uuid)
        ret = {
            'uuid': fip.uuid,
            'ip': fip.floating_ip_address
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_floating_ip_get_vmi_count(self, name, project_fqname, network_name):
        fip = self.api.floating_ip_read(fq_name=fqname(project_fqname, network_name, network_name, name))
        vmi_refs = fip.get_virtual_machine_interface_refs()
        count = 0
        if vmi_refs is not None:
            count = len(vmi_refs)
        ret = {
            'count': count
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_floating_ip_delete(self, name, project_fqname, network_name):
        fip = self.api.floating_ip_read(fq_name=fqname(project_fqname, network_name, network_name, name))
        self.api.floating_ip_delete(id=fip.uuid)
        ret = {
            'ip': fip.floating_ip_address,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_floating_ip_add_vmi(self, fip_uuid, vmi_uuid):
        fip = self._object_read("floating_ip", id=fip_uuid)
        vmi = self._object_read("virtual_machine_interface", id=vmi_uuid)
        fip.add_virtual_machine_interface(vmi)
        self.api.floating_ip_update(fip)
    
    def control_floating_ip_delete_vmi(self, name, project_fqname, network_name, vmi_name):
        fip = self._object_read("floating_ip", fqname=fqname(project_fqname, network_name, network_name, name))
        vmi = self._object_read("virtual_machine_interface", fqname=fqname(project_fqname, vmi_name))
        fip.del_virtual_machine_interface(vmi)
        self.api.floating_ip_update(fip)

    def control_instance_ip_alloc(self, project_fqname, network_name, subnet_str):
        network = self._object_read("virtual_network", fqname=fqname(project_fqname, network_name))
        ip = self.api.virtual_network_ip_alloc(network, subnet=subnet_str)
        if len(ip) != 1:
            raise RuntimeError("IP allocation failed (%d addresses allocated, 1 expected)" % len(ip))
        ret = {
            'ip': ip[0],
            'gateway': network.get_network_ipam_refs()[0]['attr'].ipam_subnets[0].default_gateway,
            'nameserver': network.get_network_ipam_refs()[0]['attr'].ipam_subnets[0].dns_server_address
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_instance_ip_free(self, project_fqname, network_name, subnet_str, ip):
        network = self._object_read("virtual_network", fqname=fqname(project_fqname, network_name))
        result = self.api.virtual_network_ip_free(network, [ip], subnet=subnet_str)
        ret = {
            'result': result,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_container_create(self, name, project_fqname, network_name):
        project = self._object_read("project", fqname_str=project_fqname)
        vm = VirtualMachine(name)
        vm_uuid = self.api.virtual_machine_create(vm)
        vmi = VirtualMachineInterface(name, project)
        network = self._object_read("virtual_network", fqname=fqname(project_fqname, network_name))
        vmi.add_virtual_network(network)
        vmi.add_virtual_machine(vm)
        vmi_uuid = self.api.virtual_machine_interface_create(vmi)
        vmi = self._object_read("virtual_machine_interface", fqname=fqname(project_fqname, name))
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
        network = self._object_read("virtual_network", id=network_uuid)
        instance_ip.add_virtual_network(network)
        vmi = self._object_read("virtual_machine_interface", id=vmi_uuid)
        instance_ip.add_virtual_machine_interface(vmi)
        uuid = self._object_create("instance_ip", instance_ip)
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
   
    def control_policy_create(self, project_fqname, src, dst):
        src_network = self._object_read("virtual_network", fqname=fqname(project_fqname, src))
        dst_network = self._object_read("virtual_network", fqname=fqname(project_fqname, dst))
        project = self._object_read("project", fqname_str=project_fqname)
        src_addr = AddressType(virtual_network=project_fqname + ":" + src)
        dst_addr = AddressType(virtual_network=project_fqname + ":" + dst)
        rule = PolicyRuleType(
                direction="<>",
                src_addresses=[src_addr],
                dst_addresses=[dst_addr],
                src_ports=[PortType()],
                dst_ports=[PortType()],
                action_list=ActionListType("pass"),
                protocol="any",
                ethertype="IPv4")
        policy = NetworkPolicy(src + "_to_" + dst, project, PolicyEntriesType([rule]))
        uuid = self._object_create("network_policy", policy)
        src_network.add_network_policy(
                policy,
                VirtualNetworkPolicyType(sequence=SequenceType(), timer=TimerType()))
        dst_network.add_network_policy(
                policy,
                VirtualNetworkPolicyType(sequence=SequenceType(), timer=TimerType()))
        self.api.virtual_network_update(src_network)
        self.api.virtual_network_update(dst_network)
        ret = {
            'uuid': uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': '))

    def control_virtual_dns_create(self, name, domain_fqname, project_name, domain_name):
        domain = self._object_read("domain", fqname_str=domain_fqname)
        dns_type = VirtualDnsType(
                domain_name=domain_name,
                record_order="random",
                external_visible=True,
                default_ttl_seconds=86400)
        dns = VirtualDns(name, domain, dns_type)
        uuid = self._object_create("virtual_DNS", dns)
        ipam = self._object_read("network_ipam", fqname=fqname(
            domain_fqname, project_name, "default-network-ipam"))
        ipam.network_ipam_mgmt = IpamType(
                ipam_dns_method="virtual-dns-server",
                ipam_dns_server=IpamDnsAddressType(virtual_dns_server_name=domain_fqname + ":" + name))
        ipam.set_virtual_DNS(dns)
        self.api.network_ipam_update(ipam)
        ret = {
            'uuid': uuid,
        }
        print json.dumps(ret, indent=4, separators=(',', ': ')) 

    def control_virtual_dns_record_create(self, name, ip, dns_uuid):
        dns = self._object_read("virtual_DNS", id=dns_uuid)
        data = VirtualDnsRecordType(name, "A", "IN", ip, 86400)
        record = VirtualDnsRecord(name, dns, data)
        uuid = self._object_create("virtual_DNS_record", record)

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

    def control_fqname_to_id(self, resource, fqname):
        uuid = self.api.fq_name_to_id(resource, fqname.split(":"))
	
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

