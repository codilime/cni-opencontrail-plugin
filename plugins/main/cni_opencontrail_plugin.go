package main

import (
	"encoding/json"
	"fmt"
	logg "log"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"

	ippkg "github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/codilime/cni-opencontrail-plugin/contrail_cli"
	"github.com/codilime/cni-opencontrail-plugin/types"
)

var (
	log *logg.Logger
)

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

func createService(netConf *types.NetConf, serviceName, serviceNetwork, subnet, vmi string) error {
	_, err := contrail_cli.CreateVirtualNetwork(netConf, serviceNetwork, subnet)
	if err != nil {
		return err
	}
	fipId, err := contrail_cli.CreateFloatingIp(
		netConf,
		serviceName,
		serviceNetwork,
		subnet)
	if err != nil {
		return err
	}
	contrail_cli.AddVmiToFloatingIp(netConf, fipId, vmi)
	log.Printf("Floating IP %s with associated VMI %s created.\n", fipId, vmi)
	return nil
}

func deleteService(netConf *types.NetConf, serviceName, serviceNetwork, vmiName string) error {
	err := contrail_cli.DeleteVmiFromFloatingIp(netConf, serviceName, serviceNetwork, vmiName)
	if err != nil {
		return err
	}
	_, err = contrail_cli.DeleteFloatingIpIfEmpty(netConf, serviceName, serviceNetwork)
	if err != nil {
		return err
	}
	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Print("ADD")

	netConf, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Create Project
	projectId, err := contrail_cli.CreateProject(netConf)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Process NetworkInfo labels
	labels := types.ParseLabels(netConf)
	log.Printf("Labels: %v\n", labels)

	// Create virtual network
	networkId, err := contrail_cli.CreateVirtualNetwork(netConf, labels.Network, netConf.PrivateSubnet)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Create Conatiner
	containerData, err := contrail_cli.CreateContainer(netConf, args.ContainerID, labels.Network)
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

	// run the IPAM plugin and get back the config to apply
	ipamResult, err := ipam.ExecAdd(netConf.IPAM.Type, args.StdinData)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	if ipamResult == nil || ipamResult.IP4 == nil {
		return fmt.Errorf("No IPv4 allocated by ipam module")
	}

	// Add port to VRouter
	err = contrail_cli.VrouterAddPort(
		netConf,
		args.ContainerID,
		projectId,
		networkId,
		containerData,
		hostInterfaceName,
		ipamResult.IP4.IP.IP.String())
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Assign IP to VMI
	_, err = contrail_cli.CreateInstanceIp(
		netConf,
		args.ContainerID,
		ipamResult.IP4.IP.IP.String(),
		networkId,
		containerData.InterfaceId)
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
	if labels.Service != "" {
		err = createService(
			netConf,
			labels.Service,
			"service-"+labels.Service,
			labels.ServiceSubnet,
			containerData.InterfaceId)
		if err != nil {
			log.Print(err.Error())
			return err
		}
		// Create network policies
		for _, service := range labels.Uses {
			_, err = contrail_cli.CreatePolicy(netConf, "service-"+labels.Service, "service-"+service)
			if err != nil {
				log.Print(err.Error())
				return err
			}
		}
	}

	// Create public IP
	if labels.Public != "" {
		err = createService(
			netConf,
			labels.Public,
			netConf.PublicNetwork,
			labels.PublicSubnet,
			containerData.InterfaceId)
		if err != nil {
			log.Print(err.Error())
			return err
		}
	}

	return ipamResult.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	log.Print("DEL")

	netConf, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Process NetworkInfo labels
	labels := types.ParseLabels(netConf)
	log.Printf("Labels: %v\n", labels)

	// Delete public IP
	if labels.Public != "" {
		err = deleteService(netConf, labels.Public, netConf.PublicNetwork, args.ContainerID)
		if err != nil {
			log.Print(err.Error())
		}
	}

	// Delete service IP
	if labels.Service != "" {
		err = deleteService(netConf, labels.Service, "service-"+labels.Service, args.ContainerID)
		if err != nil {
			log.Print(err.Error())
		}
	}

	// Delete InstanceIP
	netConf.IPAM.IP, err = contrail_cli.DeleteInstanceIp(netConf, args.ContainerID)
	if err != nil {
		log.Print(err.Error())
	}

	// Free IP address
	netConfBytes, err := json.Marshal(netConf)
	if err != nil {
		log.Printf("Cannot free ip '%s': net conf marshal failed: %v", netConf.IPAM.IP, err)
	} else {
		err = ipam.ExecDel(netConf.IPAM.Type, netConfBytes)
		if err != nil {
			log.Print(err.Error())
		}
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
	containerData, err := contrail_cli.DeleteContainer(netConf, args.ContainerID)
	if err != nil {
		log.Print(err.Error())
	}

	// Delete port from VRouter
	if containerData != nil {
		err = contrail_cli.VrouterDelPort(netConf, containerData.InterfaceId)
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
