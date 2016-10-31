package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type NetConf struct {
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

	IPAM struct {
		Type   string `json:"type"`
		Subnet string `json:"subnet"`
		IP     string `json:"ip"`
	} `json:"ipam"`

	Args struct {
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
	InterfaceId string `json:"vmi_uuid"`
	MachineId   string `json:"vm_uuid"`
	Mac         string `json:"mac"`
}

type IpData struct {
	Ip      string `json:"ip"`
	Gateway string `json:"gateway"`
}

type LabelsData struct {
	Network       string
	Service       string
	ServiceSubnet string
	Public        string
	PublicSubnet  string
	Uses          []string
}

const (
	DefaultContrailPort   = 8082
	DefaultVRouterPort    = 9090
	DefaultProject        = "default-project"
	DefaultPublicSubnet   = "172.31.0.0/16"
	DefaultPrivateSubnet  = "10.32.0.0/16"
	DefaultServiceSubnet  = "10.64.0.0/16"
	DefaultPrivateNetwork = "default-network"
	DefaultPublicNetwork  = "Public"
	AddrAllocNetwork      = "__addr_alloc__"
)

func LoadNetConf(bytes []byte) (*NetConf, error) {
	conf := &NetConf{
		ContrailPort:  DefaultContrailPort,
		VrouterPort:   DefaultVRouterPort,
		Project:       DefaultProject,
		PublicNetwork: DefaultPublicNetwork,
		PublicSubnet:  DefaultPublicSubnet,
		PrivateSubnet: DefaultPrivateSubnet,
		ServiceSubnet: DefaultServiceSubnet,
	}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return conf, nil
}

func LabelsToMap(labels []Label) map[string]string {
	ret := make(map[string]string)
	for _, label := range labels {
		ret[label.Key] = label.Value
	}
	return ret
}

func ParseLabels(netConf *NetConf) *LabelsData {
	labels := netConf.Args.OrgApacheMesos.NetworkInfo.Labels.Labels
	ret := &LabelsData{
		Network:       DefaultPrivateNetwork,
		ServiceSubnet: netConf.ServiceSubnet,
		PublicSubnet:  netConf.PublicSubnet,
		Uses:          make([]string, 0),
	}
	m := LabelsToMap(labels)

	if value, ok := m["network"]; ok {
		ret.Network = value
	}
	if value, ok := m["service"]; ok {
		ret.Service = value
	}
	if value, ok := m["service_subnet"]; ok {
		ret.ServiceSubnet = value
	}
	if value, ok := m["public"]; ok {
		ret.Public = value
	}
	if value, ok := m["public_subnet"]; ok {
		ret.PublicSubnet = value
	}
	if value, ok := m["uses"]; ok {
		ret.Uses = strings.Split(value, ",")
	}

	return ret
}
