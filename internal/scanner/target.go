package scanner

import (
	"fmt"
	"net"
)

// IsPrivateIP checks if an IP address is in a private/reserved range.
func IsPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		{mustParseCIDR("127.0.0.0/8")},
		{mustParseCIDR("169.254.0.0/16")},
		{mustParseCIDR("::1/128")},
		{mustParseCIDR("fc00::/7")},
		{mustParseCIDR("fe80::/10")},
	}

	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return network
}

// ValidateTarget checks whether a target is safe to scan.
// Returns an error if the target should not be scanned.
func ValidateTarget(target string, allowPrivate bool) error {
	ip := net.ParseIP(target)
	if ip == nil {
		// It's a hostname — resolve it to check the IP
		ips, err := net.LookupIP(target)
		if err != nil {
			return fmt.Errorf("cannot resolve target %q: %w", target, err)
		}
		if !allowPrivate {
			for _, resolved := range ips {
				if IsPrivateIP(resolved) {
					return fmt.Errorf("target %q resolves to private IP %s", target, resolved)
				}
			}
		}
		return nil
	}

	if !allowPrivate && IsPrivateIP(ip) {
		return fmt.Errorf("target %q is a private/reserved IP address", target)
	}

	return nil
}
