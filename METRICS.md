# snap plugin collector - df

## Collected Metrics
This plugin has the ability to gather the following metrics:


Namespace | Data Type | Description
----------|-----------|-----------------------
/hyperpilot/netfilter/iptables/filter/\<chain\>//stats| string | a rule of iptables
/hyperpilot/netfilter/iptables/nat/\<chain\>/stats| string | a rule of iptables
/hyperpilot/netfilter/iptables/mangle/\<chain\>/stats| string | a rule of iptables
/hyperpilot/netfilter/iptables/raw/\<chain\>/stats| string | a rule of iptables

<!-- FIXME classify metrics -->
<!-- /hyperpilot/netfilter/iptables/raw/\<chain\>/\<target\>/\<protocol\>/stats| string | a rule of iptables -->


Namespace | Data Type | Description
----------|-----------|-----------------------
/hyperpilot/netfilter/conntrack/\<service_id\>/bytes   | uint64 | a records of conntrack
/hyperpilot/netfilter/conntrack/\<service_id\>/packets | uint64 | a records of conntrack
