package k8sconntrack

type Conntrack struct {
    Host string
}

func New(host string) *Conntrack {
    return &Conntrack{Host: host}
}

