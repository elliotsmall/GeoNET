package main

import (
	"GeoNET/traffic-collector/internal/aggregator"
	"GeoNET/traffic-collector/internal/capture"
	"GeoNET/traffic-collector/internal/export"
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("error loading .env file: %v", err)
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <interface>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s eth0\n", os.Args[0])
		os.Exit(1)
	}

	endpoint, exists := os.LookupEnv("CONTROL_URL")
	if !exists {
		fmt.Fprint(os.Stderr, "CONTROL_URL environment does not exist: ")
		os.Exit(1)
	}
	if endpoint == "" {
		fmt.Fprintf(os.Stderr, "CONTROL_URL environment var exists but not set: ")
		os.Exit(1)
	}

	iface := os.Args[1]

	credential, err := export.LoadCredential()
	if err != nil {
		if os.IsNotExist(err) {
			credential, err = export.Enroll()
			if err != nil {
				log.Fatalf("enrollment failed: %v", err)
			}
		} else {
			log.Fatalf("failed to load credential: %v", err)
		}
	}

	localIPs, err := enumLocalIPs()
	if err != nil {
		log.Fatalf("enumerating local ips: %v", err)
	}

	source, err := capture.New(iface, localIPs)
	if err != nil {
		log.Fatalf("creating capture: %v", err)
	}

	exporter := export.New(endpoint, credential)

	agg := aggregator.New(source, exporter, credential.HostID, time.Second*10)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := agg.Run(ctx); err != nil {
			log.Printf("aggregator stopped: %v", err)
		}
	}()

	//Wait for signal
	<-sigChan
	log.Println("\nShutting down...")
	cancel()
	log.Println("Done!")

}

// enumLocalIPs is a helper function to enumerate list of local addresses
func enumLocalIPs() (map[netip.Addr]struct{}, error) {
	ipSet := make(map[netip.Addr]struct{})

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ipNet.IP.IsLoopback() {
			continue
		}

		if ipNet.IP.IsLinkLocalUnicast() {
			continue
		}

		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}

		ip = ip.Unmap()
		ipSet[ip] = struct{}{}
	}

	return ipSet, nil
}
