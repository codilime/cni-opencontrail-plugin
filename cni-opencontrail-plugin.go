package main

import (
	"encoding/json"
	"fmt"
	logg "log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/vishvananda/netlink"

	ippkg "github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
)

const (
	defaultProject        = "default-project"
	defaultPublicSubnet   = "172.31.0.0/16"
	defaultPrivateSubnet  = "10.32.0.0/16"
	defaultServiceSubnet  = "10.64.0.0/16"
	defaultPrivateNetwork = "default-network"
	defaultPublicNetwork  = "Public"
)

var (
	log *logg.Logger
)

type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type NetConf struct {
	types.NetConf
	ContrailServer  string   `json:"opencontrail_server"`
	ContrailPort    int      `json:"opencontrail_port"`
	VrouterPort     int      `json:"vrouter_port"`
	Project         string   `json:"project"`
	PublicNetwork   string   `json:"public_network"`
	PublicSubnet    string   `json:"public_subnet"`
	PrivateSubnet   string   `json:"private_subnet"`
	ServiceSubnet   string   `json:"service_subnet"`
	MTU             int      `json:"mtu"`
	ContrailCliCmd  string   `json:"contrail_cli_cmd"`
	ContrailCliArgs []string `json:"contrail_cli_args"`
	Args            struct {
		OrgApacheMesos struct {
			NetworkInfo struct {
				Labels struct {
					Labels []Label `json:"labels"`
				} `json:"labels"`
			} `json:"network_info"`
		} `json:"org.apache.mesos"`
	} `json:"args"`
}

type ContainerData struct {
	InterfaceId string
	MachineId   string
	Mac         string
	IP          string
}

type IpData struct {
	Ip      string
	Gateway string
}

func loadNetConf(bytes []byte) (*NetConf, error) {
	conf := &NetConf{
		Project:       defaultProject,
		PublicNetwork: defaultPublicNetwork,
		PublicSubnet:  defaultPublicSubnet,
		PrivateSubnet: defaultPrivateSubnet,
		ServiceSubnet: defaultServiceSubnet,
	}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return conf, nil
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func setupVeth(netns ns.NetNS, ifName string, mtu int) (string, error) {
	var hostVethName string

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, _, err := ippkg.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}

		hostVethName = hostVeth.Attrs().Name
		return nil
	})
	if err != nil {
		return "", err
	}

	// need to lookup hostVeth again as its index has changed during ns move
	_, err = netlink.LinkByName(hostVethName)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
	}

	return hostVethName, nil
}

func labelsToMap(labels []Label) (ret map[string]string) {
	ret = make(map[string]string)
	for _, label := range labels {
		ret[label.Key] = label.Value
	}
	return
}

func runControlCli(netConf *NetConf, args ...string) ([]byte, error) {
	cmd_args := append(
		netConf.ContrailCliArgs,
		"control",
		netConf.ContrailServer,
		strconv.Itoa(netConf.ContrailPort))
	cmd_args = append(cmd_args, args...)
	cmd := exec.Command(netConf.ContrailCliCmd, cmd_args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func runVrouterCli(netConf *NetConf, args ...string) ([]byte, error) {
	cmd_args := append(netConf.ContrailCliArgs,
		"vrouter",
		strconv.Itoa(netConf.VrouterPort))
	cmd_args = append(cmd_args, args...)
	cmd := exec.Command(netConf.ContrailCliCmd, cmd_args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func createVirtualNetwork(netConf *NetConf, name string, subnet string) (string, error) {
	output, err := runControlCli(
		netConf,
		"network_create",
		name,
		"default-domain:"+netConf.Project,
		subnet)
	if err != nil {
		return "", fmt.Errorf("Cannot create network '%s': %v: %s", name, err, string(output))
	}
	uuid := string(output)
	log.Printf("Network created: %s", uuid)
	return uuid, nil
}

func createProject(netConf *NetConf) (string, error) {
	output, err := runControlCli(
		netConf,
		"project_create",
		netConf.Project,
		"default-domain")
	if err != nil {
		return "", fmt.Errorf("Cannot create project '%s': %v: %s", netConf.Project, err, string(output))
	}
	uuid := string(output)
	log.Printf("Project created: %s", uuid)
	return uuid, nil
}

func allocFloatingIP(project string, name string, network string) (string, error) {
	log.Printf("Create floating ip '%s:%s:%s'\n", project, network, name)
	return "0.0.0.0", nil
}

func createContainer(netConf *NetConf, name string, network string, ip string) (*ContainerData, error) {
	output, err := runControlCli(
		netConf,
		"container_create",
		name,
		"default-domain:"+netConf.Project,
		network,
		ip)
	if err != nil {
		return nil, fmt.Errorf(
			"Cannot create instance '%s' in network '%s': %v: %s",
			name, network, err, string(output))
	}
	log.Printf("Instance created: %s", string(output))

	data := &ContainerData{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContainerData: %v", err)
	}
	return data, nil
}

func deleteContainer(netConf *NetConf, name string, network string) (*ContainerData, error) {
	output, err := runControlCli(
		netConf,
		"container_delete",
		name,
		"default-domain:"+netConf.Project,
		network)
	if err != nil {
		return nil, fmt.Errorf(
			"Cannot delete instance '%s' in network '%s': %v: %s",
			name, network, err, string(output))
	}
	log.Printf("Instance deleted: %s", string(output))

	data := &ContainerData{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContainerData: %v", err)
	}
	return data, nil
}

func allocInstanceIp(netConf *NetConf, network string) (*types.Result, error) {
	output, err := runControlCli(
		netConf,
		"instance_ip_alloc",
		"default-domain:"+netConf.Project,
		network,
		netConf.PrivateSubnet)
	if err != nil {
		return nil, fmt.Errorf(
			"Cannot allocate instance ip in network '%s': %v: %s",
			network, err, string(output))
	}
	log.Printf("Instance ip allocated: %s", string(output))

	data := &IpData{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IpData: %v", err)
	}

	ip := net.ParseIP(data.Ip)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP Allocated: '%s'", data.Ip)
	}

	_, ipNet, err := net.ParseCIDR(netConf.PrivateSubnet)
	if err != nil {
		log.Print(err.Error())
		return nil, err
	}
	ipNet.IP = ip

	gw := net.ParseIP(data.Gateway)
	if gw == nil {
		return nil, fmt.Errorf("Invalid Gateway ip: '%s'", data.Gateway)
	}

	_, defaultDst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		log.Print(err.Error())
		return nil, err
	}

	return &types.Result{
		IP4: &types.IPConfig{
			IP:      *ipNet,
			Gateway: gw,
			Routes: []types.Route{
				types.Route{
					Dst: *defaultDst,
					GW:  gw,
				},
			},
		},
	}, nil
}

func freeInstanceIp(netConf *NetConf, network string, ip string) error {
	output, err := runControlCli(
		netConf,
		"instance_ip_free",
		"default-domain:"+netConf.Project,
		network,
		netConf.PrivateSubnet,
		ip)
	if err != nil {
		return fmt.Errorf(
			"Cannot free instance ip in network '%s': %v: %s",
			network, err, string(output))
	}
	log.Printf("Instance ip freed: %s", string(output))
	return nil
}

func VrouterAddPort(netConf *NetConf, name string, data *ContainerData, networkId string, ifaceName string) error {
	output, err := runVrouterCli(
		netConf,
		"port_add",
		name,
		data.MachineId,
		data.InterfaceId,
		networkId,
		ifaceName,
		data.Mac)
	if err != nil {
		return fmt.Errorf("Cannot add port to vrouter: %v: %s", err, string(output))
	}
	return nil
}

func VrouterDelPort(netConf *NetConf, interfaceId string) error {
	output, err := runVrouterCli(netConf, "port_del", interfaceId)
	if err != nil {
		return fmt.Errorf("Cannot delete port from vrouter: %v: %s", err, string(output))
	}
	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Print("ADD")

	netConf, err := loadNetConf(args.StdinData)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Create Project
	_, err = createProject(netConf)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Process NetworkInfo labels
	labels := labelsToMap(
		netConf.Args.OrgApacheMesos.NetworkInfo.Labels.Labels)
	log.Printf("Labels: %v\n", labels)

	// Get private network name
	networkName, ok := labels["network"]
	if !ok {
		networkName = defaultPrivateNetwork
	}

	// Create virtual network
	_, err = createVirtualNetwork(netConf, "addr-alloc", netConf.PrivateSubnet)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	networkId, err := createVirtualNetwork(netConf, networkName, netConf.PrivateSubnet)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Allocate IP address
	ipamResult, err := allocInstanceIp(netConf, networkName)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	if ipamResult == nil || ipamResult.IP4 == nil {
		return fmt.Errorf("No IPv4 allocated by ipam module")
	}

	// Create Conatiner
	containerData, err := createContainer(
		netConf,
		args.ContainerID,
		networkName,
		ipamResult.IP4.IP.IP.String())
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Get network namespace
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		log.Print(err.Error())
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// Create Veth interfaces
	hostInterfaceName, err := setupVeth(netns, args.IfName, netConf.MTU)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	log.Printf("Virtual interface %s created.", hostInterfaceName)

	// Add port to VRouter
	err = VrouterAddPort(
		netConf,
		args.ContainerID,
		containerData,
		networkId,
		hostInterfaceName)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Configure interface
	err = netns.Do(func(_ ns.NetNS) error {
		err := ipam.ConfigureIface(args.IfName, ipamResult)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		iface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			log.Print(err.Error())
			return fmt.Errorf("failed to lookup %q: %v", args.IfName, err)
		}
		hwAddr, err := net.ParseMAC(containerData.Mac)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		//err = ippkg.SetHWAddrByIP(args.IfName, result.IP4.IP.IP, nil)
		err = netlink.LinkSetHardwareAddr(iface, hwAddr)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		return nil
	})
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Create service
	service, ok := labels["service"]
	if ok {
		_, err = createVirtualNetwork(netConf, "addr-alloc", netConf.ServiceSubnet)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		serviceNetwork := "service-" + service
		_, err = createVirtualNetwork(netConf, serviceNetwork, netConf.ServiceSubnet)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		ip, err := allocFloatingIP(
			netConf.Project,
			serviceNetwork,
			serviceNetwork+"-FIP")
		if err != nil {
			log.Print(err.Error())
			return err
		}
		log.Printf("Floating IP: %s\n", ip)
	}

	// Create Public floating IP
	_, ok = labels["export_ip"]
	if ok {
		_, err = createVirtualNetwork(netConf, "addr-alloc", netConf.PublicSubnet)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		_, err := createVirtualNetwork(netConf, netConf.PublicNetwork, netConf.PublicSubnet)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		ip, err := allocFloatingIP(
			netConf.Project,
			netConf.PublicNetwork,
			netConf.PublicNetwork+"FIP")
		if err != nil {
			log.Print(err.Error())
			return err
		}
		log.Printf("Public IP: %s\n", ip)
	}

	return ipamResult.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	log.Print("DEL")

	netConf, err := loadNetConf(args.StdinData)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Process NetworkInfo labels
	labels := labelsToMap(
		netConf.Args.OrgApacheMesos.NetworkInfo.Labels.Labels)
	log.Printf("Labels: %v\n", labels)

	// Get private network name
	networkName, ok := labels["network"]
	if !ok {
		networkName = defaultPrivateNetwork
	}

	// Delete veth interfaces
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		_, err = ippkg.DelLinkByNameAddr(args.IfName, netlink.FAMILY_V4)
		return err
	})
	if err != nil {
		log.Print(err.Error())
	}

	// Delete Conatiner
	containerData, err := deleteContainer(
		netConf,
		args.ContainerID,
		networkName)
	if err != nil {
		log.Print(err.Error())
	}

	// Free IP address
	if containerData != nil {
		err = freeInstanceIp(netConf, networkName, containerData.IP)
		if err != nil {
			log.Print(err.Error())
		}
	}

	// Delete port from VRouter
	if containerData != nil {
		err = VrouterDelPort(netConf, containerData.InterfaceId)
		if err != nil {
			log.Print(err.Error())
		}
	}

	return nil
}

func main() {
	f, _ := os.OpenFile(
		"/var/log/cni-contrail-plugin.log",
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0666)
	log = logg.New(
		f,
		"CNI: "+os.Getenv("CNI_CONTAINERID")+": ",
		logg.Ldate|logg.Ltime|logg.Lshortfile)

	skel.PluginMain(cmdAdd, cmdDel, version.Legacy)

	log.Printf("DONE!")
	f.Close()
}
