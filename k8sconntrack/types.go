package k8sconntrack

type Conntrack struct {
	Host string
}

func NewConntrack(host string) *Conntrack {
	return &Conntrack{Host: host}
}
