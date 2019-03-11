package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	logger "log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/google/gopacket/pcap"
)

const (
	snaplen     = 1 << 16
	promiscuous = true
	timeout     = pcap.BlockForever
)

var (
	iface  = flag.String("i", "en4", "name/ip of local nic")
	osrcip = flag.String("osrc", "192.168.1.1", "original source ip address")
	nsrcip = flag.String("nsrc", "192.168.1.200", "new source ip address")
	oip    net.IP
	nip    net.IP
	h      *pcap.Handle
	local  localini
	enter  = bufio.NewScanner(os.Stdin)
)

type udppacket struct {
	eth     layers.Ethernet
	ip      layers.IPv4
	udp     layers.UDP
	payload []byte
}

func init() {
	flag.Parse()
	oip, nip = net.ParseIP(*osrcip), net.ParseIP(*nsrcip)
	if oip == nil || nip == nil {
		log.Printf("Must provide original and new source ip.\n")
		flag.Usage()
		os.Exit(1)
	}
	oip, nip = oip.To4(), nip.To4()

	if err := local.set(*iface); err != nil {
		log.Fatalf("error with local interface: %+v", err)
	}
}

func main() {
	log := logger.New(os.Stdout, "", logger.LstdFlags)
	var err error
	// open sniffer
	h, err = pcap.OpenLive(local.DevName, snaplen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("could not open capture device: %+v", err)
	}
	defer h.Close()

	// set capture filter
	bpf := "udp and (ip host " + oip.String() + ")"
	if err := h.SetBPFFilter(bpf); err != nil {
		log.Fatal("error with bpf: ", err)
	}
	// if err := h.SetDirection(pcap.DirectionOut); err != nil {
	// 	log.Fatal("could net set direction: ", err)
	// }

	inpacket := udppacket{}
	decoded := make([]gopacket.LayerType, 0, 10)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&inpacket.eth,
		&inpacket.ip,
		&inpacket.udp,
	)

	c := make(chan udppacket, 100)

	go func() {
		for {
			p, _, err := h.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					return
				}
				continue
			}
			// payload := getpayload(inpacket.payload)
			parser.IgnoreUnsupported = true
			if err := parser.DecodeLayers(p, &decoded); err != nil {
				log.Println("decode err: ", err)
			}
			c <- udppacket{
				eth:     inpacket.eth,
				ip:      inpacket.ip,
				udp:     inpacket.udp,
				payload: inpacket.udp.LayerPayload(),
			}
		}
	}()

	// done channel
	done := make(chan bool)
	go func() {
		done <- enter.Scan()
	}()

	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	log.Printf("listening for udp on address %s, fix to address %s", oip.String(), nip.String())
	for {
		select {
		case p := <-c:
			p.ip.SrcIP = nip
			p.udp.SetNetworkLayerForChecksum(&p.ip)
			if err := gopacket.SerializeLayers(buff, opts, &p.eth, &p.ip, &p.udp, gopacket.Payload(p.payload)); err != nil {
				log.Println("serial err: ", err)
				continue
			}

			if err := h.WritePacketData(buff.Bytes()); err != nil {
				log.Println("sending err: ", err)
				continue
			}
		case <-done:
			log.Println("exiting...")
			return
		}
	}

}
