package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	logger "log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/google/gopacket/pcap"
)

const (
	snaplen     = 1 << 16
	promiscuous = true
	timeout     = pcap.BlockForever
	maxTTL      = 10 * time.Minute
)

var (
	rx       = flag.String("rx", "en4", "name/ip of receiving nic")
	tx       = flag.String("tx", "en4", "name/ip of transmitting nic")
	nsrcip   = flag.String("nsrc", "192.168.1.200", "new source ip address for transmitting")
	nip      net.IP
	htx, hrx *pcap.Handle
	ltx, lrx localini
	enter    = bufio.NewScanner(os.Stdin)
)

// E is a conveniecy for error printing
type E struct {
	error
	string
}

type udppacket struct {
	eth     layers.Ethernet
	ip      layers.IPv4
	udp     layers.UDP
	payload []byte
}

func init() {
	flag.Parse()
	nip = net.ParseIP(*nsrcip)
	if nip == nil {
		log.Printf("Must provide new source ip.\n")
		flag.Usage()
		os.Exit(1)
	}
	nip = nip.To4()

	if err := ltx.set(*tx); err != nil {
		log.Fatalf("error setting local transmitting interface: %+v", E{err, err.Error()})
	}
	if err := lrx.set(*rx); err != nil {
		log.Fatalf("error setting local receiving interface: %+v", E{err, err.Error()})
	}
}

func main() {
	log := logger.New(os.Stdout, "[UDPFIX]", logger.LstdFlags)
	var err error

	// open tx rx sniffers
	htx, err := pcap.OpenLive(ltx.DevName, snaplen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("could not open capture device (transmitting): %+v", E{err, err.Error()})
	}
	defer htx.Close()
	hrx, err = pcap.OpenLive(lrx.DevName, snaplen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("could not open capture device (receiving): %+v", E{err, err.Error()})
	}
	defer hrx.Close()

	// set capture filters
	bpftx := "udp and (ip src host " + ltx.IP.String() + ")"
	if err := htx.SetBPFFilter(bpftx); err != nil {
		log.Fatalf("error with tx bpf: %+v\n", E{err, err.Error()})
	}
	bpfrx := "udp and (ip dst host " + lrx.IP.String() + ")"
	if err := hrx.SetBPFFilter(bpfrx); err != nil {
		log.Fatalf("error with rx bpf: %+v\n", E{err, err.Error()})
	}

	// start rx sniffing loop
	m := newTTLmap(maxTTL)
	go func() {
		var (
			rxip  layers.IPv4
			rxudp layers.UDP
		)
		decoded := make([]gopacket.LayerType, 0, 2)
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&rxip,
			&rxudp,
		)
		parser.IgnoreUnsupported = true
		for {
			p, _, err := hrx.ZeroCopyReadPacketData()
			if err != nil {
				if err == io.EOF {
					return
				}
				continue
			}
			if err := parser.DecodeLayers(p, &decoded); err != nil {
				continue
			}
			m.putPort(newMKey(rxip.SrcIP, rxudp.SrcPort), rxudp.DstPort)
		}
	}()

	inpacket := udppacket{}
	decoded := make([]gopacket.LayerType, 0, 10)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&inpacket.eth,
		&inpacket.ip,
		&inpacket.udp,
	)
	parser.IgnoreUnsupported = true

	c := make(chan udppacket, 100)

	go func() {
		for {
			p, _, err := htx.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					return
				}
				continue
			}
			// payload := getpayload(inpacket.payload)
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
	log.Printf("receiving on: %s transmitting on: %s new source address: %s\n", lrx.IP, ltx.IP, nip)
	for {
		select {
		case p := <-c:
			p.ip.SrcIP = nip
			// sport := m.getPort(newMKey(p.ip.DstIP, p.udp.DstPort))
			sport, ok := m.m[newMKey(p.ip.DstIP, p.udp.DstPort)]
			if !ok || sport.port == 0 {
				continue
			}
			p.udp.SrcPort = sport.port
			p.udp.SetNetworkLayerForChecksum(&p.ip)
			if err := gopacket.SerializeLayers(buff, opts, &p.eth, &p.ip, &p.udp, gopacket.Payload(p.payload)); err != nil {
				log.Println("serial err: ", err)
				continue
			}

			if err := htx.WritePacketData(buff.Bytes()); err != nil {
				log.Println("sending err: ", err)
				continue
			}
		case <-done:
			log.Println("exiting...")
			return
		}
	}

}
