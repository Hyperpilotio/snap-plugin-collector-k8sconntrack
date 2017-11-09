package k8sconntrack

import (
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/resty.v1"
	//"github.com/Hyperpilotio/snap-plugin-collector-k8sconntrack/pkg/logger"
)

func init() {
	resty.DefaultClient.
		SetRetryCount(3).
		SetRetryWaitTime(3 * time.Second).
		SetRetryMaxWaitTime(15 * time.Second)
}

type _Transaction struct {
	ServiceID   string `json:"serviceID"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type Transaction struct {
	ServiceID       string             `json:"serviceID"`
	EndpointCounter map[string]float64 `json:"endpointCounter"`
	EndpointAbs     map[string]int64   `json:"endpointAbs"`
}

// GetTransactions retrieve conntrack data from k8sconntrack
func (con *Conntrack) GetTransactions() ([]Transaction, error) {
	resp, err := resty.R().Get(fmt.Sprintf("http://%s/transactions", con.Host))
	if err != nil {
		msg := fmt.Errorf("Unable to get conntrack stats from k8sconntrack: %s", err.Error())
		log.WithFields(log.Fields{"Host": con.Host}).
			Error(msg.Error())
		return nil, msg

	}

	var t []Transaction
	err = json.Unmarshal(resp.Body(), &t)
	if err != nil {
		log.Errorf("Unable to parse body of response: err: %s body: %s", err.Error(), resp.String())
		return nil, err
	}
	return t, nil
}
