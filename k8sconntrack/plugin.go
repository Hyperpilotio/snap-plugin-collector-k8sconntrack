// +build linux

/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2015 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8sconntrack

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/intelsdi-x/snap-plugin-lib-go/v1/plugin"
	"github.com/intelsdi-x/snap/control/plugin/cpolicy"
	"github.com/intelsdi-x/snap/core"
)

const (
	// PluginName df collector plugin name
	PluginName = "k8sconntrack"
	// Version of plugin
	Version = 1

	nsVendor = "hyperpilot"
	nsClass  = "netfilter"
)

var (
	// prefix in metric namespace
	namespacePrefix = []string{nsVendor, nsClass}

	iptablesNamespacePrefix = append(namespacePrefix, "iptables")
	iptablesMetrics         = map[string][]string{
		"filter": []string{"input", "output", "forward"},
		"nat":    []string{"prerouting", "postrouting", "output"},
		"mangle": []string{"prerouting", "output", "forward", "input", "postrouting"},
		"raw":    []string{"prerouting", "output"},
	}

	conntrackNamespacePrefix = append(namespacePrefix, "conntrack")
	conntrackMetrics         = []string{
		"bytes",
		"packets",
	}
)

// GetMetricTypes returns list of available metric types
// It returns error in case retrieval was not successful
func (c *ctCollector) GetMetricTypes(cfg plugin.Config) ([]plugin.Metric, error) {
	if !c.initialized {
		if err := c.init(cfg); err != nil {
			return nil, err
		}
	}
	mts := []plugin.Metric{}
	iptablesMetrics, err := c.conntrack.ListChains()
	if err == nil {
		for table, chains := range *iptablesMetrics {
			for _, chain := range chains {
				mts = append(mts, plugin.Metric{
					Namespace: core.NewNamespace(iptablesNamespacePrefix...).
						AddStaticElement(table).
						AddDynamicElement(chain, "name of chain").
						AddStaticElement("stats"),
					Description: fmt.Sprintf("dynamic iptables metric: %s table %s chain", table, chain),
					Version:     Version,
				})
			}
		}
	} else {
		c.logger.Errorf("Unable to retrieve chains of iptables from k8sconntrack: %s", err.Error())
	}

	for _, kind := range conntrackMetrics {
		mts = append(mts, plugin.Metric{
			Namespace: core.NewNamespace(conntrackNamespacePrefix...).
				AddStaticElement(kind),
			Description: "dynamic conntrack metric: " + kind,
			Version:     Version,
		})
	}
	return mts, nil
}

// GetConfigPolicy returns config policy
// It returns error in case retrieval was not successful
func (c *ctCollector) GetConfigPolicy() (*cpolicy.ConfigPolicy, error) {
	cp := cpolicy.New()
	node := cpolicy.NewPolicyNode()
	cp.Add([]string{nsVendor, nsClass, PluginName}, node)
	rule1, _ := cpolicy.NewStringRule("host", false, "localhost:3000")
	node.Add(rule1)
	return cp, nil
}

// func (c *ctCollector) CollectMetrics(mts []plugin.MetricType) ([]plugin.MetricType, error) {
// }

func (c *ctCollector) init(cfg plugin.Config) error {
	if c.initialized {
		return nil
	}

	host, err := cfg.GetString("host")
	if err != nil {
		return err
	}
	c.conntrack = NewConntrack(host)

	return nil
}

// NewDfCollector creates new instance of plugin and returns pointer to initialized object.
func NewCtCollector() *ctCollector {
	logger := log.New()
	imutex := new(sync.Mutex)
	// FIXME should not specify address
	return &ctCollector{
		logger: logger,
		mutex:  imutex,
	}
}

type ctCollector struct {
	mutex       *sync.Mutex
	logger      *log.Logger
	conntrack   *Conntrack
	initialized bool
}
