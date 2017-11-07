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

	. "github.com/smartystreets/goconvey/convey"
	// "github.com/stretchr/testify/mock"
	// "github.com/stretchr/testify/suite"

	"github.com/intelsdi-x/snap/control/plugin"
)

func TestGetMetricTypes(t *testing.T) {
	Convey("Given ct plugin is initialized", t, func() {
		ct := NewCtCollector()

		Convey("When values for given metrics are requested", func() {
			mts, err := ct.GetMetricTypes(plugin.ConfigType{})

			Convey("Then no error should be reported", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then proper metrics are returned", func() {
				ns := []string{}
				for _, m := range mts {
					ns = append(ns, m.Namespace().String())
				}
				So(len(mts), ShouldEqual, 15)
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
