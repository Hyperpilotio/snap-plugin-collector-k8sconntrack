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
	"strings"
	"sync"
	"time"

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
	// iptablesMetrics         = map[string][]string{
	// 	"filter": []string{"input", "output", "forward"},
	// 	"nat":    []string{"prerouting", "postrouting", "output"},
	// 	"mangle": []string{"prerouting", "output", "forward", "input", "postrouting"},
	// 	"raw":    []string{"prerouting", "output"},
	// }

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

	// Iptables stats
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

	// Conntrack stats
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

	iptablesMetrics, err := c.conntrack.GetIptables()
	if err != nil {
		log.Warnf("%s", err.Error())
	}

	cMetrics, err := c.conntrack.GetTransactions()
	if err != nil {
		log.Warnf("%s", err.Error())
	}

	for _, metricType := range mts {
		namespace := metricType.Namespace()
		lns := len(namespace)
		if lns < 4 {
			return nil, fmt.Errorf("Wrong namespace length %d: should be at least ", lns)
		}
		switch namespace[2].Value {
		case "iptables":
			// using namespace /hyperpilot/netfilter/iptables/*
			if lns == 4 {
				if namespace[3].Value != "*" {
					return nil, fmt.Errorf("Namespace should contain wildcard")
				}
				for _, table := range iptablesMetrics {
					for _, chain := range table.Chains {
						for _, data := range chain.Data {
							ns := make([]core.NamespaceElement, IptablesMetricLength)
							copy(ns, namespace)
							ns[3].Name = "table"
							ns[3].Value = table.Name
							ns[4].Name = "chain"
							ns[4].Value = chain.Name
							ns[5].Name = "stats"
							ns[5].Value = "stats"

							newMetric := plugin.MetricType{
								Timestamp_: time.Now(),
								Namespace_: ns,
								Data_:      strings.Join(data, " "),
							}
							metrics = append(metrics, newMetric)
						}
					}
				}
				break
			} else if lns == 5 {
				// using namespace /hyperpilot/netfilter/iptables/<table>/*
				if namespace[4].Value != "*" {
					return nil, fmt.Errorf("Namespace should contain wildcard")
				}
				if table, ok := iptablesMetrics[namespace[3].Value]; ok {
					for _, chain := range table.Chains {
						for _, data := range chain.Data {
							ns := make([]core.NamespaceElement, IptablesMetricLength)
							copy(ns, namespace)
							ns[3].Name = "table"
							ns[3].Value = table.Name
							ns[4].Name = "chain"
							ns[4].Value = chain.Name
							ns[5].Name = "stats"
							ns[5].Value = "stats"

							newMetric := plugin.MetricType{
								Timestamp_: time.Now(),
								Namespace_: ns,
								Data_:      strings.Join(data, " "),
							}
							metrics = append(metrics, newMetric)
						}
					}
				}
			} else if lns == 6 {
				if namespace[3].Value == "*" && namespace[4].Value == "*" {
					// using namespace /hyperpilot/netfilter/iptables/*/*/stats
					for _, table := range iptablesMetrics {
						for _, chain := range table.Chains {
							for _, data := range chain.Data {
								ns := make([]core.NamespaceElement, IptablesMetricLength)
								copy(ns, namespace)
								ns[3].Name = "table"
								ns[3].Value = table.Name
								ns[4].Name = "chain"
								ns[4].Value = chain.Name
								ns[5].Name = "stats"
								ns[5].Value = "stats"

								newMetric := plugin.MetricType{
									Timestamp_: time.Now(),
									Namespace_: ns,
									Data_:      strings.Join(data, " "),
								}

								metrics = append(metrics, newMetric)
							}
						}
					}
					break
				} else if namespace[3].Value != "*" && namespace[4].Value == "*" {
					if table, ok := iptablesMetrics[namespace[3].Value]; ok {
						// using namespace /hyperpilot/netfilter/iptables/<table>/*/stats
						for _, chain := range table.Chains {
							if len(chain.Data) == 0 {
								continue
							}
							for _, rule := range chain.Data {
								ns := make([]core.NamespaceElement, IptablesMetricLength)
								copy(ns, namespace)
								ns[3].Name = "table"
								ns[3].Value = table.Name
								ns[4].Name = "chain"
								ns[4].Value = chain.Name
								ns[5].Name = "stats"
								ns[5].Value = "stats"
								newMetric := plugin.MetricType{
									Timestamp_: time.Now(),
									Namespace_: ns,
									Data_:      strings.Join(rule, " "),
								}
								metrics = append(metrics, newMetric)
							}
						}
						break
					} else {
						return nil, fmt.Errorf("specified metrics are not available: %s", namespace.String())
					}
				} else if namespace[3].Value != "*" && namespace[4].Value != "*" {
					// using namespace /hyperpilot/netfilter/iptables/<table>/<chain>/stats
					if table, ok := iptablesMetrics[namespace[3].Value]; ok {
						for _, chain := range table.Chains {
							if chain.Name == namespace[4].Value {
								ns := make([]core.NamespaceElement, IptablesMetricLength)
								copy(ns, namespace)
								ns[3].Name = "table"
								ns[3].Value = table.Name
								ns[4].Name = "chain"
								ns[4].Value = chain.Name
								ns[5].Name = "stats"
								ns[5].Value = "stats"

								for _, data := range chain.Data {
									newMetric := plugin.MetricType{
										Timestamp_: time.Now(),
										Namespace_: ns,
										Data_:      strings.Join(data, " "),
									}
									metrics = append(metrics, newMetric)
								}
							}
						}
					}
					break
				}
			}
		case "conntrack":
			if lns == 4 {
				if namespace[lns-1].Value != "*" {
					return nil, fmt.Errorf("Namespace should contain wildcard")
				}
				// use namespace /hyperpilot/netfilter/conntrack/*
				// FIXME 還沒有實作選擇 bytes or packets 在這邊 還有在 k8sconntrack
				for _, transaction := range cMetrics {
					ns := make([]core.NamespaceElement, ConntrackMetricLength)
					copy(ns, namespace)
					ns[3].Name = "service_id"
					ns[3].Value = transaction.ServiceID
					newMetric := plugin.MetricType{
						Timestamp_: time.Now(),
						Namespace_: ns,
						Data_:      transaction.EndpointAbs,
					}

					metrics = append(metrics, newMetric)
				}
			} else if lns == 5 {
				if namespace[3].Value == "*" && namespace[4].Value == "*" {
					// use namespace /hyperpilot/netfilter/conntrack/*/*
					for _, transaction := range cMetrics {
						ns := make([]core.NamespaceElement, 5)
						copy(ns, namespace)
						ns[3].Name = "service_id"
						ns[3].Value = transaction.ServiceID
						newMetric := plugin.MetricType{
							Timestamp_: time.Now(),
							Namespace_: ns,
							Data_:      transaction.EndpointAbs,
						}

						metrics = append(metrics, newMetric)
					}
				} else if namespace[3].Value == "*" {
					// use namespace /hyperpilot/netfilter/conntrack/*/bytes
					for _, transaction := range cMetrics {
						ns := make([]core.NamespaceElement, ConntrackMetricLength)
						copy(ns, namespace)
						ns[3].Name = "service_id"
						ns[3].Value = transaction.ServiceID
						ns[4].Name = "stats"
						ns[4].Value = namespace[4].Value
						newMetric := plugin.MetricType{
							Timestamp_: time.Now(),
							Namespace_: ns,
							Data_:      transaction.EndpointAbs,
						}
						metrics = append(metrics, newMetric)
					}
				}
			}
		}
	}
	return metrics, nil
}

func (c *ctCollector) init(cfg interface{}) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	host, err := config.GetConfigItem(cfg, "host")
	if err != nil {
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
