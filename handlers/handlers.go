package handlers

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

var privateIPBlocks []*net.IPNet

func init() {
	err := os.MkdirAll(LOG_PATH, os.ModePerm)
	if err != nil {
		panic(err)
	}

	customFormatter := new(log.JSONFormatter)
	customFormatter.TimestampFormat = time.RFC1123
	log.SetFormatter(customFormatter)

	output := &lumberjack.Logger{
		Filename:   LOG_PATH + filepath.Base(os.Args[0]) + ".log",
		MaxSize:    2,
		MaxBackups: 1,
		MaxAge:     5,
		Compress:   true,
	}

	ioMW := io.MultiWriter(output, os.Stdout)

	log.SetOutput(ioMW)

	log.SetLevel(log.InfoLevel)

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
