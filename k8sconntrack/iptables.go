package k8sconntrack

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Hyperpilotio/snap-plugin-collector-k8sconntrack/pkg/log"
	"gopkg.in/resty.v1"
)

var (
	Tables = [...]string{"filter", "nat", "mangle", "raw"}
)

/*
Chain
Name is the name of the chain
Data is
ex:[
    "277786",           // packets
    "493629126",        // bytes
    "KUBE-SERVICES",    // target
    "all",              // prot
    "--",               // opt
    "*",                // in
    "*",                // out
    "0.0.0.0/0",        //source
    "0.0.0.0/0",        // destination
    "\/* kubernetes service portals *\/"
   ]
*/
type Chain struct {
	Name string     `json:"Name"`
	Data [][]string `json:"Data"`
}

type Table struct {
	Name   string  `json:"Name"`
	Chains []Chain `json:"Chains"`
}

// FIXME should let api server return all iptables instead of querying particular tables
func (con *Conntrack) GetIptables(tables []string) ([]Table, error) {
	var endpoint string
	if len(tables) < 1 {
		return []Table{}, errors.New("tables are not specified")
	}

	endpoint = fmt.Sprintf("http://%s/iptables?Table=%s",
		con.Host, strings.Join(tables, "&Table="))
	resp, err := resty.R().Get(endpoint)
	if err != nil {
		msg := fmt.Errorf("Unable to get iptables stats from k8sconntrack: %s", err.Error())
		log.WithFields(log.Fields{"Host": con.Host}).
			Error(msg.Error())
		return nil, msg

	}

	var t []Table
	err = json.Unmarshal(resp.Body(), &t)
	if err != nil {
		log.Errorf("Unable to parse body of response: err: %s body: %s", err.Error(), resp.String())
		return nil, err
	}

	return t, nil
}

func (con *Conntrack) ListChains() (*map[string][]string, error) {
	resp, err := resty.R().Get(fmt.Sprintf("http://%s/iptables/chains", con.Host))
	if err != nil {
		msg := fmt.Errorf("Unable to get iptables stats from k8sconntrack: %s", err.Error())
		log.WithFields(log.Fields{"Host": con.Host}).
			Error(msg.Error())
		return nil, msg

	}

	var chains map[string][]string
	err = json.Unmarshal(resp.Body(), &chains)
	if err != nil {
		log.Errorf("Unable to parse body of response: err: %s body: %s", err.Error(), resp.String())
		return nil, err
	}

	return &chains, nil
}
