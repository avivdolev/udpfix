package main

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	maxTTL = 10 * time.Minute
)

type mkey struct {
	ip, port gopacket.Endpoint
}

func newMKey(ip net.IP, port layers.UDPPort) mkey {
	return mkey{
		ip:   layers.NewIPEndpoint(ip),
		port: layers.NewUDPPortEndpoint(port),
	}
}

type mval struct {
	port   layers.UDPPort
	access int64
}

// func (k1 *mkey) Equal(k2 mkey) bool {
// 	if k1.ip.FastHash() == k2.ip.FastHash() {
// 		return k1.port.FastHash() == k2.port.FastHash()
// 	}
// 	return false
// }

// TTLmap is a map with item expirety and renewal
// a new map fires goroutine to clean expired items
type TTLmap struct {
	m map[mkey]*mval
	l sync.Mutex
}

func newTTLmap(ttl int) (m *TTLmap) {
	m = &TTLmap{
		m: make(map[mkey]*mval),
	}
	go func() {
		t := time.NewTicker(time.Duration(ttl))
		defer t.Stop()
		for tick := range t.C {
			m.l.Lock()
			for k, v := range m.m {
				if tick.Unix()-v.access >= int64(ttl) {
					delete(m.m, k)
				}
			}
			m.l.Unlock()
		}
	}()
	return
}

func (m *TTLmap) getPort(k mkey) layers.UDPPort {
	m.l.Lock()
	defer m.l.Unlock()
	v, ok := m.m[k]
	if !ok {
		return 0
	}
	v.access = time.Now().Unix()
	return v.port
}

func (m *TTLmap) putPort(k mkey, p layers.UDPPort) {
	m.l.Lock()
	defer m.l.Unlock()
	m.m[k] = &mval{
		port:   p,
		access: time.Now().Unix(),
	}
}
