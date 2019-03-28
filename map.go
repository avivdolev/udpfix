package main

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// TTLmap is a map with item expirety and renewal
// a new map fires goroutine to clean expired items
type TTLmap struct {
	m map[mkey]*mval
	l sync.Mutex
}

func newTTLmap(ttl time.Duration) (m *TTLmap) {
	m = &TTLmap{
		m: make(map[mkey]*mval),
	}
	go func() {
		t := time.NewTicker(ttl)
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

func (m *TTLmap) getPort(k mkey) (v *mval, ok bool) {
	m.l.Lock()
	defer m.l.Unlock()
	v, ok = m.m[k]
	return
}

func (m *TTLmap) putPort(k mkey, p layers.UDPPort) {
	m.l.Lock()
	defer m.l.Unlock()
	m.m[k] = &mval{
		port:   p,
		access: time.Now().Unix(),
	}
}
