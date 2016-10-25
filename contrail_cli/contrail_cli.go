package contrail_cli

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/codilime/cni-opencontrail-plugin/types"
)

type response struct {
	UUID             string `json:"uuid"`
	IP               string `json:"ip"`
	FloatingIpId     string `json:"floating_ip_uuid"`
	FloatingIpPoolId string `json:"floating_ip_pool_uuid"`
}

func runControlCli(netConf *types.NetConf, args ...string) ([]byte, error) {
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

func runVrouterCli(netConf *types.NetConf, args ...string) ([]byte, error) {
	cmd_args := append(netConf.ContrailCliArgs,
		"vrouter",
		strconv.Itoa(netConf.VrouterPort))
	cmd_args = append(cmd_args, args...)
	cmd := exec.Command(netConf.ContrailCliCmd, cmd_args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func CreateVirtualNetwork(netConf *types.NetConf, name string, subnet string) (string, error) {
	output, err := runControlCli(
		netConf,
		"network_create",
		name,
		"default-domain:"+netConf.Project,
		subnet)
	if err != nil {
		return "", fmt.Errorf("Cannot create network '%s': %v: %s", name, err, string(output))
	}
	data := &response{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return "", fmt.Errorf("failed to parse response from contrail_cli.py: %v: %s", err, string(output))
	}
	return data.UUID, nil
}

func CreateFloatingIp(netConf *types.NetConf, name, networkName, subnet, ip, vmi string) (string, error) {
	output, err := runControlCli(
		netConf,
		"floating_ip_create",
		name,
		"default-domain:"+netConf.Project,
		networkName,
		subnet,
		ip,
		vmi)
	if err != nil {
		return "", fmt.Errorf("Cannot create floating IP '%s': %v: %s", name, err, string(output))
	}
	data := &response{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return "", fmt.Errorf("failed to parse response from contrail_cli.py: %v: %s", err, string(output))
	}
	return data.FloatingIpId, nil
}

func CreateProject(netConf *types.NetConf) (string, error) {
	output, err := runControlCli(
		netConf,
		"project_create",
		netConf.Project,
		"default-domain")
	if err != nil {
		return "", fmt.Errorf("Cannot create project '%s': %v: %s", netConf.Project, err, string(output))
	}
	data := &response{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return "", fmt.Errorf("failed to parse response from contrail_cli.py: %v: %s", err, string(output))
	}
	return data.UUID, nil
}

func CreateContainer(netConf *types.NetConf, name, network string) (*types.ContainerData, error) {
	output, err := runControlCli(
		netConf,
		"container_create",
		name,
		"default-domain:"+netConf.Project,
		network)
	if err != nil {
		return nil, fmt.Errorf(
			"Cannot create instance '%s': %v: %s",
			name, err, string(output))
	}

	data := &types.ContainerData{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse types.ContainerData: %v", err)
	}
	return data, nil
}

func DeleteContainer(netConf *types.NetConf, name string) (*types.ContainerData, error) {
	output, err := runControlCli(
		netConf,
		"container_delete",
		name,
		"default-domain:"+netConf.Project)
	if err != nil {
		return nil, fmt.Errorf(
			"Cannot delete instance '%s'': %v: %s",
			name, err, string(output))
	}

	data := &types.ContainerData{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse types.ContainerData: %v", err)
	}
	return data, nil
}

func CreateInstanceIp(netConf *types.NetConf, name, ip, networkId, vmiId string) (string, error) {
	output, err := runControlCli(
		netConf,
		"instance_ip_create",
		name,
		ip,
		networkId,
		vmiId)
	if err != nil {
		return "", fmt.Errorf(
			"Cannot create instance ip '%s' (%s): %v: %s",
			name, ip, err, string(output))
	}
	data := &response{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return "", fmt.Errorf("failed to parse response from contrail_cli.py: %v: %s", err, string(output))
	}
	return data.UUID, nil
}

func DeleteInstanceIp(netConf *types.NetConf, name string) (string, error) {
	output, err := runControlCli(
		netConf,
		"instance_ip_delete",
		name)
	if err != nil {
		return "", fmt.Errorf(
			"Cannot delete instance ip '%s': %v: %s",
			name, err, string(output))
	}
	data := &response{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return "", fmt.Errorf("failed to parse response from contrail_cli.py: %v: %s", err, string(output))
	}
	return data.IP, nil
}

func VrouterAddPort(
	netConf *types.NetConf,
	name string,
	projectId,
	networkId string,
	data *types.ContainerData,
	ifaceName string,
	ip string) error {
	output, err := runVrouterCli(
		netConf,
		"port_add",
		name,
		projectId,
		networkId,
		data.MachineId,
		data.InterfaceId,
		ifaceName,
		data.Mac,
		ip)
	if err != nil {
		return fmt.Errorf("Cannot add port to vrouter: %v: %s", err, string(output))
	}
	return nil
}

func VrouterDelPort(netConf *types.NetConf, interfaceId string) error {
	output, err := runVrouterCli(netConf, "port_del", interfaceId)
	if err != nil {
		return fmt.Errorf("Cannot delete port from vrouter: %v: %s", err, string(output))
	}
	return nil
}

func AllocIpAddress(netConf *types.NetConf, network, subnet string) (*types.IpData, error) {
	output, err := runControlCli(
		netConf,
		"instance_ip_alloc",
		"default-domain:"+netConf.Project,
		network,
		subnet)
	if err != nil {
		return nil, fmt.Errorf(
			"Cannot allocate IP in network '%s': %v: %s",
			network, err, string(output))
	}

	data := &types.IpData{}
	err = json.Unmarshal(output, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IpData: %v", err)
	}
	return data, nil
}

func FreeIpAddress(netConf *types.NetConf, network string, ip string) ([]byte, error) {
	output, err := runControlCli(
		netConf,
		"instance_ip_free",
		"default-domain:"+netConf.Project,
		network,
		netConf.IPAM.Subnet,
		ip)
	if err != nil {
		return nil, fmt.Errorf(
			"Cannot free ip '%s' in network '%s': %v: %s",
			ip, network, err, string(output))
	}
	return output, err
}
