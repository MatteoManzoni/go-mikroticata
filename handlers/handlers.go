package handlers

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
)

var privateIPBlocks []*net.IPNet
const PUBIP_RESOLVE_ENDPOINT = "https://api.ipify.org?format=text"

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func IPisPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func IsIpBlacklisted(ip net.IP, blacklist []net.IP) bool {
	for _, blacklistedIP  := range blacklist {
		if blacklistedIP.Equal(ip) {
			return true
		}
	}
	return false
}

func RetriveWanIP() (net.IP, error) {

	resp, err := http.Get(PUBIP_RESOLVE_ENDPOINT)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ipString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(string(ipString))

	return ip, nil
}