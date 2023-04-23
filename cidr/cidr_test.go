package cidr

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testCIDR4(t *testing.T, s string) CIDR {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf(`testCIDR4: net.ParseCIDR(%#v) failed: %v`, s, err)
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		t.Fatalf(`testCIDR4: IP address is not an IPv4 addresss: %#v`, s)
	}
	ones, _ := ipNet.Mask.Size()
	return CIDR{
		IP:         ip,
		PrefixBits: ones,
	}
}

func testCIDR6(t *testing.T, s string) CIDR {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf(`testCIDR6: net.ParseCIDR(%#v) failed: %v`, s, err)
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 32 {
		ones += 96
	}
	return CIDR{
		IP:         ip,
		PrefixBits: ones,
	}
}

func Test_CIDR(t *testing.T) {
	t.Run("IsIPv4", func(t *testing.T) {
		t.Run("Case1", func(t *testing.T) {
			c := testCIDR4(t, "0.0.0.0/0")
			assert.Equal(t, true, c.IsIPv4())
		})
		t.Run("Case2", func(t *testing.T) {
			c := testCIDR6(t, "::/0")
			assert.Equal(t, false, c.IsIPv4())
		})
	})
	t.Run("Other", func(t *testing.T) {
		t.Run("Case1", func(t *testing.T) {
			c := testCIDR4(t, "192.168.6.0/23")
			actual := c.Other()
			expected := testCIDR4(t, "192.168.4.0/23")
			assert.Equal(t, expected, actual)
		})
		t.Run("Case2", func(t *testing.T) {
			c := testCIDR4(t, "192.168.4.0/23")
			actual := c.Other()
			expected := testCIDR4(t, "192.168.6.0/23")
			assert.Equal(t, expected, actual)
		})
		t.Run("Case3", func(t *testing.T) {
			c := testCIDR6(t, "::ffff:ffff/128")
			actual := c.Other()
			expected := testCIDR6(t, "::ffff:fffe/128")
			assert.Equal(t, expected, actual)
		})
		t.Run("Case4", func(t *testing.T) {
			c := testCIDR6(t, "::ffff:fffe/128")
			actual := c.Other()
			expected := testCIDR6(t, "::ffff:ffff/128")
			assert.Equal(t, expected, actual)
		})
		t.Run("Case5", func(t *testing.T) {
			assert.PanicsWithError(t, "Other on /0 or invalid CIDR", func() {
				CIDR{PrefixBits: -1}.Other()
			})
		})
		t.Run("Case6", func(t *testing.T) {
			assert.PanicsWithError(t, "Other on /0 or invalid CIDR", func() {
				CIDR{PrefixBits: 1}.Other()
			})
		})
		t.Run("Case7", func(t *testing.T) {
			assert.PanicsWithError(t, "Other on /0 or invalid CIDR", func() {
				CIDR{IP: make(net.IP, 1), PrefixBits: 10}.Other()
			})
		})
	})
	t.Run("String", func(t *testing.T) {
		t.Run("Case1", func(t *testing.T) {
			actual := testCIDR6(t, "::/0").String()
			assert.Equal(t, "::/0", actual)
		})
		t.Run("Case2", func(t *testing.T) {
			actual := testCIDR6(t, "168.192.0.0/32").String()
			assert.Equal(t, "::ffff:a8c0:0/128", actual)
		})
		t.Run("Case3", func(t *testing.T) {
			actual := testCIDR6(t, "::168.192.0.0/5").String()
			assert.Equal(t, "::a8c0:0/5", actual)
		})
	})
}

func Test_ParseCIDR(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		x := ipTo4
		ipTo4 = func(net.IP) net.IP {
			return nil
		}
		defer func() {
			ipTo4 = x
		}()
		_, err := ParseCIDR(`127.0.0.1/32`)
		assert.ErrorContains(t, err, `CIDR notation is unexpectedly invalid`)
	})
	t.Run("Table", func(t *testing.T) {
		type testCase struct {
			Expected CIDR
			Input    string
			ErrText  string
		}
		for _, tc := range []testCase{
			{
				Expected: testCIDR6(t, "::/0"),
				Input:    "::/0",
			},
			{
				Expected: testCIDR6(t, "::/64"),
				Input:    "::/64",
			},
			{
				Expected: testCIDR4(t, "0.0.0.0/0"),
				Input:    "0.0.0.0/0",
			},
			{
				Expected: testCIDR4(t, "168.192.0.0/16"),
				Input:    "168.192.0.0/16",
			},
			{
				ErrText: "invalid CIDR address",
				Input:   "asdf",
			},
			{
				ErrText: "IP address is not the first IP address",
				Input:   "1.0.0.0/0",
			},
		} {
			actual, err := ParseCIDR(tc.Input)
			if err != nil {
				if tc.ErrText == "" {
					t.Errorf(`ParseCIDR(%#v) gave unexpected error: %v`, tc.Input, err)
				} else {
					assert.ErrorContainsf(t, err, tc.ErrText, `ParseCIDR(%#v)`, tc.Input)
				}
			} else {
				assert.Equalf(t, tc.Expected, actual, `ParseCIDR(%#v)`, tc.Input)
			}
		}
	})
}

func Test_IPString(t *testing.T) {
	type testCase struct {
		Input    net.IP
		Expected string
	}
	for _, tc := range []testCase{
		{
			Expected: "::",
			Input:    make(net.IP, 16),
		},
		{
			Input:    make(net.IP, 4),
			Expected: "0.0.0.0",
		},
		{
			Input:    net.ParseIP("::ffff:127.0.0.1"),
			Expected: "::ffff:7f00:1",
		},
	} {
		actual := ipString(tc.Input)
		assert.Equalf(t, tc.Expected, actual, `ipString(%#v)`, tc.Input)
	}
}

func Test_ipCopy(t *testing.T) {
	expected := net.IP{1, 2, 3, 4}
	actual := ipCopy(expected)
	assert.Equal(t, expected, actual)
	assert.NotSame(t, &expected[0], &actual[0])
}

func Test_ipSetBit(t *testing.T) {
	t.Run("Case1", func(t *testing.T) {
		ip := net.ParseIP("0.0.0.0")
		newIP := ipSetBit(ip, 96+31)
		actual := newIP.String()
		const expected = "0.0.0.1"
		assert.Equal(t, expected, actual)
	})
	t.Run("Case2", func(t *testing.T) {
		ip := net.ParseIP("192.168.128.0")
		newIP := ipSetBit(ip, 96+26)
		actual := newIP.String()
		const expected = "192.168.128.32"
		assert.Equal(t, expected, actual)
	})
	t.Run("Case3", func(t *testing.T) {
		ip := net.ParseIP("0.0.0.0")
		newIP := ipSetBit(ip, 96)
		actual := newIP.String()
		const expected = "128.0.0.0"
		assert.Equal(t, expected, actual)
	})
}
