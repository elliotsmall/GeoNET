package main

import (
	"GeoNET/traffic-collector/internal/ebpf"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <interface>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s eth0\n", os.Args[0])
		os.Exit(1)
	}

	iface := os.Args[1]

	log.Printf("Starting GeoNET Monitor on interface: %s\n", iface)
	log.Printf("Press Ctrl+C to stop monitor")

	//Create monitor
	monitor, err := ebpf.NewMonitor(iface)
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}
	defer monitor.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			flowCount, hsCount, err := monitor.GetMapStats()
			if err != nil {
				log.Printf("Error getting map stats: %v", err)
			} else {
				log.Printf("Map Stats: %d flows, %d handshakes", flowCount, hsCount)
			}
		}
	}()

	//Wait for signal
	<-sigChan
	log.Println("\nShutting down...")
	ticker.Stop()
	log.Println("Done!")

}
