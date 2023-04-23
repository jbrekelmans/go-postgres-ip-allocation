package cidr

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
)

var ipTo4 = (net.IP).To4

type CIDR struct {
	// IP is the IP address that is identifies the network, and is also the address of
	// the first host in the subnetwork.
	// len(IP) must be either 4 or 16, and is used to discriminate IPv4 from IPv6.
	IP net.IP

	// PrefixBits returns the number of bits identifying the network represented by this CIDR.
	PrefixBits int
}

var _ fmt.Stringer = (*CIDR)(nil)
var _ sql.Scanner = (*CIDR)(nil)

func ParseCIDR(s string) (CIDR, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return CIDR{}, err
	}
	if !ip.Equal(ipNet.IP) {
		return CIDR{}, fmt.Errorf(`CIDR notation is invalid: IP address is not the first IP address`)
	}
	isIPv6 := strings.IndexByte(s, ':') >= 0
	if !isIPv6 {
		ip4 := ipTo4(ip)
		if ip4 == nil {
			return CIDR{}, fmt.Errorf(`CIDR notation is unexpectedly invalid: %#v`, s)
		}
		ip = ip4
	}
	ones, _ := ipNet.Mask.Size()
	return CIDR{
		IP:         ip,
		PrefixBits: ones,
	}, nil
}

func MustParseCIDR(s string) CIDR {
	c, err := ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return c
}

// IsIPv4 returns true if and only if this CIDR represents an IPv4 network.
func (c CIDR) IsIPv4() bool {
	return len(c.IP) == net.IPv4len
}

func (c CIDR) IsLower() bool {
	if c.PrefixBits == 0 {
		return false
	}
	bitIndex := c.PrefixBits - 1
	return !ipGetBit(c.IP, bitIndex)
}

// Other returns the unambiguous other CIDR paired with c, say x, such
// that x and c have a common prefix of length c.PrefixBits - 1.
//
// For example:
// MustParseCIDR("0.0.0.0/32").Other().String() == "0.0.0.1/32"
// MustParseCIDR("0.0.0.1/32").Other().String() == "0.0.0.0/32"
//
// If c.PrefixBits = 0 or c is invalid then panics.
// x.Other().Other() is equal to x for all x.
func (c CIDR) Other() CIDR {
	if c.PrefixBits <= 0 || c.PrefixBits > len(c.IP)*8 {
		panic(errors.New("Other on /0 or invalid CIDR"))
	}
	bitIndex := c.PrefixBits - 1
	return CIDR{
		IP:         ipFlipBit(ipCopy(c.IP), bitIndex),
		PrefixBits: c.PrefixBits,
	}
}

// Scan implements the "database/sql".Scanner interface.
func (c *CIDR) Scan(src any) error {
	if c == nil {
		return fmt.Errorf(`(*CIDR).Scan: receiver is nil`)
	}
	if srcStr, ok := src.(string); ok {
		var err error
		*c, err = ParseCIDR(srcStr)
		if err != nil {
			return fmt.Errorf(`(*CIDR).Scan: invalid string: %w`, err)
		}
		return nil
	}
	*c = CIDR{}
	return fmt.Errorf(`(*CIDR).Scan: unsupported type/value %T (%#v)`, src, src)
}

// Split splits the CIDR in two and returns the upper half.
// Split panics if the CIDR is invalid, or is a /32 or /128 CIDR.
func (c CIDR) Split() CIDR {
	bitIndex := c.PrefixBits
	return CIDR{
		IP:         ipSetBit(ipCopy(c.IP), bitIndex),
		PrefixBits: c.PrefixBits + 1,
	}
}

func (c CIDR) String() string {
	return fmt.Sprintf("%s/%d", ipString(c.IP), c.PrefixBits)
}

// ipString converts ip to a string.
// ipString(ip) and ip.String() return equal strings,
// except that ipString(ip) only returns an IPv4 string if len(ip) == 4.
// For example: ipString(net.ParseIP("127.0.0.1")) == "::7f00:1"
//     whereas:  net.ParseIP("127.0.0.1").String() == "127.0.0.1".
func ipString(ip net.IP) string {
	if len(ip) == net.IPv6len {
		ip4 := ip.To4()
		if ip4 != nil {
			ipCopy := append(net.IP(nil), ip...)
			ipCopy[1] = 1
			s := ipCopy.String()
			return s[1:]
		}
	}
	return ip.String()
}

func ipCopy(ip net.IP) net.IP {
	return append(net.IP(nil), ip...)
}

func ipFlipBit(ip net.IP, bitIndex int) net.IP {
	j := 7 - (bitIndex & 7)
	bit := byte(1 << j)
	ip[bitIndex>>3] ^= bit
	return ip
}

func ipGetBit(ip net.IP, bitIndex int) bool {
	j := 7 - (bitIndex & 7)
	bit := byte(1 << j)
	return (ip[bitIndex>>3] & bit) != 0
}

func ipSetBit(ip net.IP, bitIndex int) net.IP {
	j := 7 - (bitIndex & 7)
	bit := byte(1 << j)
	ip[bitIndex>>3] |= bit
	return ip
}
