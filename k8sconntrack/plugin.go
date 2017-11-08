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

	"github.com/intelsdi-x/snap-plugin-utilities/config"
	"github.com/intelsdi-x/snap/control/plugin"
	"github.com/intelsdi-x/snap/control/plugin/cpolicy"
	"github.com/intelsdi-x/snap/core"

	"github.com/Hyperpilotio/snap-plugin-collector-k8sconntrack/pkg/log"
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
func (c *ctCollector) GetMetricTypes(cfg plugin.ConfigType) ([]plugin.MetricType, error) {
	if !c.initialized {
		if err := c.init(cfg); err != nil {
			return nil, err
		}
	}

	mts := []plugin.MetricType{}
	iptablesMetrics, err := c.conntrack.ListChains()
	if err == nil {
		for table, chains := range *iptablesMetrics {
			for _, chain := range chains {
				mts = append(mts, plugin.MetricType{
					Namespace_: core.NewNamespace(iptablesNamespacePrefix...).
						AddStaticElement(table).
						AddDynamicElement(chain, "name of chain").
						AddStaticElement("stats"),
					Description_: fmt.Sprintf("dynamic iptables metric: %s table %s chain", table, chain),
					Version_:     Version,
				})
			}
		}
	} else {
		log.Errorf("Unable to retrieve chains of iptables from k8sconntrack: %s", err.Error())
	}

	for _, kind := range conntrackMetrics {
		mts = append(mts, plugin.MetricType{
			Namespace_: core.NewNamespace(conntrackNamespacePrefix...).
				AddStaticElement(kind),
			Description_: "dynamic conntrack metric: " + kind,
			Version_:     Version,
		})
	}
	return mts, nil
}

// GetConfigPolicy returns config policy
// It returns error in case retrieval was not successful
func (c *ctCollector) GetConfigPolicy() (*cpolicy.ConfigPolicy, error) {
	cp := cpolicy.New()

	rule, _ := cpolicy.NewStringRule("host", false, "localhost:3000")
	node := cpolicy.NewPolicyNode()
	node.Add(rule)
	cp.Add([]string{nsVendor, nsClass, PluginName}, node)

	return cp, nil
}

func (c *ctCollector) CollectMetrics(mts []plugin.MetricType) ([]plugin.MetricType, error) {
	if !c.initialized {
		if err := c.init(mts[0]); err != nil {
			return nil, err
		}
	}

	metrics := []plugin.MetricType{}
	return metrics, nil
}

func (c *ctCollector) init(cfg interface{}) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	host, err := config.GetConfigItem(cfg, "host")
	if err != nil {
		log.Errorln("host: ", host)
		return err
	}

	c.conntrack = NewConntrack(host.(string))

	return nil
}

// NewCtCollector creates new instance of plugin and returns pointer to initialized object.
func NewCtCollector() *ctCollector {
	return &ctCollector{
		mutex: new(sync.Mutex),
	}
}

// Meta returns plugin's metadata
func Meta() *plugin.PluginMeta {
	return plugin.NewPluginMeta(
		PluginName,
		Version,
		plugin.CollectorPluginType,
		[]string{plugin.SnapGOBContentType},
		[]string{plugin.SnapGOBContentType},
		plugin.RoutingStrategy(plugin.StickyRouting),
		plugin.ConcurrencyCount(1),
	)
}

type ctCollector struct {
	mutex       *sync.Mutex
	conntrack   *Conntrack
	initialized bool
}
