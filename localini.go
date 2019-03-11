package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

type localini struct {
	IP      net.IP
	MAC     net.HardwareAddr
	DevName string
	Name    string
}

func (l *localini) set(s string) error {
	ip := net.ParseIP(s)
	switch ip {
	case nil:
		ifi, err := net.InterfaceByName(s)
		if err != nil {
			return nil
		}
		l.MAC, l.Name = ifi.HardwareAddr, ifi.Name
		addrs, err := ifi.Addrs()
		if err != nil {
			return err
		}
		if addrs == nil {
			return fmt.Errorf("no address found for interface: %s details: %+v", s, l)
		}
		l.IP, _, err = net.ParseCIDR(addrs[0].String())
		if err != nil {
			return err
		}
	default:
		l.IP = ip
		if err := l.findMAC(); err != nil {
			return err
		}
	}

	if err := l.findDevName(); err != nil {
		return err
	}

	return nil
}

func (l *localini) findDevName() error {
	ifis, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	for _, ifi := range ifis {
		for _, a := range ifi.Addresses {
			if l.IP.Equal(a.IP) {
				l.DevName = ifi.Name
				return nil
			}
		}
	}
	return fmt.Errorf("no interface matched input ip: %+v", l)
}

func (l *localini) findMAC() error {
	ifis, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, ifi := range ifis {
		addrs, err := ifi.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if l.IP.Equal(ip) {
				l.MAC, l.Name = ifi.HardwareAddr, ifi.Name
			}
		}
	}
	return fmt.Errorf("could not find local interface: %+v", err)
}
