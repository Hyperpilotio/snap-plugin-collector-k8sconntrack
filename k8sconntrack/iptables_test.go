package k8sconntrack

import (
    "testing"
    . "github.com/smartystreets/goconvey/convey"
)

func TestGetIptables(t *testing.T) {
    Convey("Configure a conntrack client", t, func() {
        c := New("localhost:3000")
        Convey("Should be able to derive nat table", func() {
            table, err := c.GetIptables([]string{"filter"})
            So(err, ShouldEqual, nil)
            So(table, ShouldNotEqual, nil)
        })
    })
}
