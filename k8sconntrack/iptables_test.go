package k8sconntrack

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetIptables(t *testing.T) {
	Convey("Configure a conntrack client", t, func() {
		c := NewConntrack("localhost:3000")
		Convey("Should be able to derive nat table", func() {
			metricsMap, err := c.GetIptables()
			So(err, ShouldEqual, nil)
			So(len(metricsMap), ShouldNotEqual, 0)
		})
	})
}

func TestListChains(t *testing.T) {
	Convey("Configure a conntrack client", t, func() {
		c := NewConntrack("localhost:3000")
		Convey("Should be able to derive all chains of iptables", func() {
			chains, err := c.ListChains()
			So(err, ShouldEqual, nil)
			So(chains, ShouldNotEqual, nil)
		})
	})
}
