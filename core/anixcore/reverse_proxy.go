package anixcore

import (
	"fmt"
	"sort"
	"strings"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
)

// The plan's reverse proxies run as anixcore `reverse_proxy` inbounds
// (networkcore inbound-reverse-proxy), one per reverse proxy, tagged
// reverseProxyTagPrefix + id, next to the port forwards and synced with
// them (syncForwards). A reverse proxy with a certificate terminates TLS
// with it inline. Upstreams are dialed by the next hop's outbound, like a
// forward's targets, and their health is reported the same way.

// reverseProxyTagPrefix starts the inbound tag of a reverse proxy.
const reverseProxyTagPrefix = "rproxy-"

// reverseProxyFeature is the kernel feature that runs reverse proxies.
const reverseProxyFeature = "reverse_proxy"

// reverseProxyInbounds answers the reverse_proxy inbounds of plan's
// reverse proxies, by tag.
func reverseProxyInbounds(plan *networkv1.NetworkPlan) (map[string]map[string]any, error) {
	transports := map[string]*networkv1.Transport{}
	for _, transport := range plan.GetTransports() {
		transports[transport.GetId()] = transport
	}
	inbounds := map[string]map[string]any{}
	for _, proxy := range plan.GetReverseProxies() {
		tag := reverseProxyTagPrefix + proxy.GetId()
		inbound := map[string]any{
			"tag": tag, "type": "reverse_proxy",
			"listen": proxy.GetListen().GetAddress(), "listen_port": proxy.GetListen().GetPort(),
		}
		switch {
		case proxy.GetEgressId() != "":
			inbound["outbound"] = "egress:" + proxy.GetEgressId()
		case proxy.GetTransportId() != "":
			transport := transports[proxy.GetTransportId()]
			if transport.GetKind() != network.TransportAnxLine || transport.GetRole() != networkv1.TransportRole_TRANSPORT_ROLE_DIAL {
				return nil, fmt.Errorf("reverse proxy %s: transport %s is not a dialing anx_line transport", proxy.GetId(), proxy.GetTransportId())
			}
			inbound["outbound"] = "anx-line:" + transport.GetId()
		default:
			return nil, fmt.Errorf("reverse proxy %s: no next hop", proxy.GetId())
		}
		if proxy.GetCertificatePem() != "" {
			inbound["tls"] = map[string]any{
				"certificate": proxy.GetCertificatePem(), "key": proxy.GetPrivateKeyPem(), "alpn": []string{"http/1.1"},
			}
			inbound["forwarded_proto"] = "https"
		}
		sites := make([]map[string]any, 0, len(proxy.GetSites()))
		for _, site := range proxy.GetSites() {
			entry := map[string]any{"hosts": site.GetHosts()}
			if site.GetRedirectHttps() {
				entry["redirect_https"] = true
			} else {
				entry["routes"] = proxyRoutes(site.GetRoutes())
			}
			sites = append(sites, entry)
		}
		inbound["sites"] = sites
		inbounds[tag] = inbound
	}
	return inbounds, nil
}

func proxyRoutes(routes []*networkv1.ReverseProxyRoute) []map[string]any {
	out := make([]map[string]any, 0, len(routes))
	for _, route := range routes {
		entry := map[string]any{}
		if path := route.GetPath(); path != "" && path != "/" {
			entry["path"] = path
		}
		if route.GetStripPrefix() {
			entry["strip_prefix"] = true
		}
		if host := route.GetHost(); host != "" {
			entry["host"] = host
		} else if header := route.GetHostHeader(); header != "" {
			entry["host_header"] = header
		}
		if len(route.GetHeaders()) > 0 {
			entry["headers"] = route.GetHeaders()
		}
		upstreams := make([]map[string]any, 0, len(route.GetUpstreams()))
		for _, upstream := range route.GetUpstreams() {
			target := map[string]any{"server": upstream.GetHost(), "server_port": upstream.GetPort()}
			if upstream.GetWeight() > 0 {
				target["weight"] = upstream.GetWeight()
			}
			if upstream.GetPriority() > 0 {
				target["priority"] = upstream.GetPriority()
			}
			upstreams = append(upstreams, target)
		}
		entry["upstreams"] = upstreams
		// Balance, health and breaker read as a forward's; the rest is
		// refused by the plan check.
		forwardPolicy(entry, route.GetPolicy())
		out = append(out, entry)
	}
	return out
}

// splitForwardTags splits the tags of held inbounds into port forwards and
// reverse proxies.
func splitForwardTags(tags []string) (forwards, proxies []string) {
	for _, tag := range tags {
		if strings.HasPrefix(tag, reverseProxyTagPrefix) {
			proxies = append(proxies, tag)
		} else {
			forwards = append(forwards, tag)
		}
	}
	return forwards, proxies
}

// reverseProxyStatus answers one status per reverse proxy anixcore runs,
// and a down one for each of unsupported (a kernel without the feature).
func reverseProxyStatus(client *client, tags []string, unsupported []string) []*networkv1.ReverseProxyStatus {
	var statuses []*networkv1.ReverseProxyStatus
	for _, forward := range forwardStatus(client, tags) {
		statuses = append(statuses, &networkv1.ReverseProxyStatus{
			Id: strings.TrimPrefix(forward.GetId(), reverseProxyTagPrefix), State: forward.GetState(), Detail: forward.GetDetail(),
			UpBytes: forward.GetUpBytes(), DownBytes: forward.GetDownBytes(), Upstreams: forward.GetTargets(),
		})
	}
	for _, id := range unsupported {
		statuses = append(statuses, &networkv1.ReverseProxyStatus{
			Id: id, State: networkv1.ComponentState_COMPONENT_STATE_DOWN,
			Detail: "this anx-node has no reverse_proxy feature; upgrade the kernel",
		})
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].GetId() < statuses[j].GetId() })
	return statuses
}
