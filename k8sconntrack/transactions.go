package k8sconntrack

import (
    "fmt"
    "encoding/json"

    "gopkg.in/resty.v1"

    //"github.com/Hyperpilotio/snap-plugin-collector-k8sconntrack/pkg/logger"

)

type _Transaction struct {
    ServiceID    string `json:"serviceID"`
    Source       string `json:"source"`
    Destination  string `json:"destination"`
}

type Transaction struct {
    ServiceID       string `json:"serviceID"`
    EndpointCounter map[string]float64`json:"endpointCounter"`
    EndpointAbs     map[string]int64 `json:"endpointAbs"`
}


func (con *Conntrack) GetTransactions() ([]Transaction, error) {
    resp, err := resty.R().Get(fmt.Sprintf("http://%s/transactions", con.Host))
    if err != nil {
        //FIXME appropreate log level
        //logger.Warn("Unable to get iptables stats from k8sconntrack: Host %s ", con.Host)
        //logger.WithFields(host ).Warn("msg=%s", err.Error())
        return nil, err

    }
    if resp.StatusCode() != 200 {
        //logger.WithFields().Warn("Unable to get iptables stats from k8sconntrack")
        return nil, fmt.Errorf("Status of request: %v", resp.Status())
    }

    var t []Transaction
    err = json.Unmarshal(resp.Body(), &t)
    if err != nil {
        //logger.WithFields().Warnf("Unable to parse body of response: %s", resp.String())
        fmt.Println(resp.String())
        return nil, err
    }

    return t, nil
}
