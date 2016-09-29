package types

import (
	"encoding/json"
	"fmt"
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
	InterfaceId string
	MachineId   string
	Mac         string
}

type IpData struct {
	Ip      string
	Gateway string
}

type LabelsData struct {
	Network string
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

func ParseLabels(labels []Label) *LabelsData {
	ret := &LabelsData{
		Network: DefaultPrivateNetwork,
	}
	m := LabelsToMap(labels)

	if value, ok := m["network"]; ok {
		ret.Network = value
	}

	return ret
}
