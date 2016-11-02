package main

import (
	"fmt"
	logg "log"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/codilime/cni-opencontrail-plugin/contrail_cli"
	"github.com/codilime/cni-opencontrail-plugin/types"
)

var (
	log *logg.Logger
)

type IpamNetConf struct {
	IPAM struct {
	}
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Print("IPAM ADD")

	netConf, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Create addr_alloc virtual network
	networkId, _, err := contrail_cli.CreateVirtualNetwork(
		netConf, types.AddrAllocNetwork, netConf.IPAM.Subnet)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	log.Printf(types.AddrAllocNetwork+" created (uuid=%s)", networkId)

	// Alloc IP
	data, err := contrail_cli.AllocIpAddress(netConf, types.AddrAllocNetwork, netConf.IPAM.Subnet)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	ip := net.ParseIP(data.Ip)
	if ip == nil {
		log.Print(err.Error())
		return fmt.Errorf("Invalid IP Allocated: '%s'", data.Ip)
	}

	_, ipNet, err := net.ParseCIDR(netConf.PrivateSubnet)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	ipNet.IP = ip

	gw := net.ParseIP(data.Gateway)
	if gw == nil {
		log.Print(err.Error())
		return fmt.Errorf("Invalid Gateway ip: '%s'", data.Gateway)
	}

	_, defaultDst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		log.Print(err.Error())
		return err
	}

	result := &cniTypes.Result{
		IP4: &cniTypes.IPConfig{
			IP:      *ipNet,
			Gateway: gw,
			Routes: []cniTypes.Route{
				cniTypes.Route{
					Dst: *defaultDst,
					GW:  gw,
				},
			},
		},
	}

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	log.Print("IPAM DEL")

	netConf, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		log.Print(err.Error())
		return err
	}

	// Free IP address
	_, err = contrail_cli.FreeIpAddress(netConf, types.AddrAllocNetwork, netConf.IPAM.IP)
	if err != nil {
		log.Print(err.Error())
		return err
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

	log.Printf("IPAM DONE!")
	f.Close()
}
