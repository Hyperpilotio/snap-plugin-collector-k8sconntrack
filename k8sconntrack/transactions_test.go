package k8sconntrack

import (
    "testing"
    . "github.com/smartystreets/goconvey/convey"
)

func TestGetTransactions(t *testing.T) {
    Convey("Configure a conntrack client", t, func() {
        c := New("localhost:3000")
        Convey("Should be able to derive transactions data", func() {
            transactions, err := c.GetTransactions()
            So(err, ShouldEqual, nil)
            So(transactions, ShouldNotEqual, nil)
        })
    })
}
