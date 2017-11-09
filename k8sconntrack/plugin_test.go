/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2015 hyperpilot Corporation

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
	"testing"

	"github.com/intelsdi-x/snap/core"
	"github.com/intelsdi-x/snap/core/cdata"
	"github.com/intelsdi-x/snap/core/ctypes"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/intelsdi-x/snap/control/plugin"
)

func TestGetMetricTypes(t *testing.T) {
	Convey("Given ct plugin is initialized", t, func() {
		ct := NewCtCollector()
		cfg := func() plugin.ConfigType {
			node := cdata.NewNode()
			node.AddItem("host", ctypes.ConfigValueStr{Value: "localhost:3000"})
			return plugin.ConfigType{ConfigDataNode: node}
		}()

		Convey("When values for given metrics are requested", func() {
			mts, err := ct.GetMetricTypes(cfg)

			Convey("Then no error should be reported", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then proper metrics are returned", func() {
				ns := []string{}
				for _, m := range mts {
					ns = append(ns, m.Namespace().String())
				}

				So(ns, ShouldContain, "/hyperpilot/netfilter/iptables/filter/*/stats")
				So(ns, ShouldContain, "/hyperpilot/netfilter/iptables/nat/*/stats")
				So(ns, ShouldContain, "/hyperpilot/netfilter/iptables/mangle/*/stats")
				So(ns, ShouldContain, "/hyperpilot/netfilter/iptables/raw/*/stats")

				So(ns, ShouldContain, "/hyperpilot/netfilter/conntrack/bytes")
				So(ns, ShouldContain, "/hyperpilot/netfilter/conntrack/packets")
			})
		})
	})
}

func TestCollectMetrics(t *testing.T) {
	Convey("Given a set metric types", t, func() {
		ct := NewCtCollector()
		cfg := func() plugin.ConfigType {
			node := cdata.NewNode()
			node.AddItem("host", ctypes.ConfigValueStr{Value: "localhost:3000"})
			return plugin.ConfigType{ConfigDataNode: node}
		}()
		m1 := plugin.MetricType{
			Namespace_: core.NewNamespace("hyperpilot", "netfilter", "iptables", "filter", "*", "stats"),
			Config_:    cfg.ConfigDataNode}
		m2 := plugin.MetricType{
			Namespace_: core.NewNamespace("hyperpilot", "netfilter", "conntrack", "*", "bytes"),
			Config_:    cfg.ConfigDataNode}
		m3 := plugin.MetricType{
			Namespace_: core.NewNamespace("hyperpilot", "netfilter", "conntrack", "*", "packets"),
			Config_:    cfg.ConfigDataNode}

		metricTypes := []plugin.MetricType{m1, m2, m3}

		Convey("When values for given metrics are requested", func() {
			mts, err := ct.CollectMetrics(metricTypes)

			Convey("Then no error should be reported", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then proper metrics are returned", func() {
				ns := []string{}
				for _, m := range mts {
					ns = append(ns, m.Namespace().String())
				}

				So(ns, ShouldContain, "/hyperpilot/netfilter/iptables/filter/output/stats")
			})

			Convey("When values for specified metrics are requested", func() {
				type testCase struct {
					Description string
					Value       interface{}
				}
				testSet := []testCase{
					testCase{
						Description: "[iptables] len == 4",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "iptables", "*"),
					},
					testCase{
						Description: "[iptables] len == 5, with two wildcard fields",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "iptables", "*", "*"),
					},
					testCase{
						Description: "[iptables] len == 5, with one wildcard filed",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "iptables", "filter", "*"),
					},
					testCase{
						Description: "[iptables] len == 6, with two wildcard fields",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "iptables", "*", "*", "stats"),
					},
					testCase{
						Description: "[iptables] len == 6, with one wildcard field",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "iptables", "filter", "*", "stats"),
					},
					testCase{
						Description: "[iptables] len == 6, with zero wildcard fields",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "iptables", "filter", "output", "stats"),
					},
					testCase{
						Description: "[conntrack] len == 4, with one wildcard field",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "conntrack", "*"),
					},
					testCase{
						Description: "[conntrack] len == 5, with one wildcard field",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "conntrack", "*", "bytes"),
					},
					testCase{
						Description: "[conntrack] len == 5, with two wildcard fields",
						Value:       core.NewNamespace("hyperpilot", "netfilter", "conntrack", "*", "*"),
					},
				}

				for _, val := range testSet {
					m := plugin.MetricType{
						Namespace_: val.Value.(core.Namespace),
						Config_:    cfg.ConfigDataNode,
					}
					metricTypes := []plugin.MetricType{m}
					_, err := ct.CollectMetrics(metricTypes)

					Convey(val.Description, func() {
						Convey("Then no error should be reported", func() {
							So(err, ShouldBeNil)
						})
					})
				}
			})
		})
	})

}
