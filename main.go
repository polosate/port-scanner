package main

import (
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/t94j0/nmap"

	"github.com/polosate/port-scanner/store"
)

var (
	xlog = slog.New(slog.NewTextHandler(os.Stdout, nil))
)

func main() {
	xlog.Info("nmap scanner")

	kv := store.KVStoreDefault()

	input, err := kv.Get("INPUT")
	if err != nil {
		xlog.Error("failed to get input from kv store", "error", err)
		return
	}
	rawHosts := input["hosts"].([]interface{})
	var hosts []string
	for _, t := range rawHosts {
		hosts = append(hosts, t.(string))
	}

	scan(hosts, &kv)

	xlog.Info("actor is done")
}

func scan(hosts []string, kv *store.KVStore) {
	resultChan := make(chan Output, 1000)
	hostChan := make(chan string, len(hosts))

	const workerCount = 5
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range hostChan {
				timeStart := time.Now()

				res, err := nmap.Init().
					AddHosts(ip).
					AddFlags("-Pn", "-sT", "-T4", "-p-", "-n", "--min-rate", "500", "--max-rate", "2500").
					Run()

				if err != nil {
					xlog.Error("Scan error", "host", ip, "error", err)
					continue
				}

				for _, host := range res.Hosts {
					o := Output{
						Host:     host.Address,
						TCPPorts: map[string]State{},
						UDPPorts: map[string]State{},
					}
					for _, port := range host.Ports {
						if port.State == "open" {
							if port.Protocol == "tcp" {
								o.TCPPorts[strconv.FormatUint(uint64(port.ID), 10)] = State{State: port.State}
							}
							if port.Protocol == "udp" {
								o.UDPPorts[strconv.FormatUint(uint64(port.ID), 10)] = State{State: port.State}
							}
						}
					}
					resultChan <- o
				}
				elapsed := time.Since(timeStart)
				xlog.Info("elapsed time", "host", ip, "time", elapsed.String())
			}
		}()
	}

	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for res := range resultChan {
			xlog.Info("saving scan result to dataset", "host", res.Host)
			if err := kv.PutToDataset(res); err != nil {
				xlog.Error("error while add result to dataset", "host", res.Host, "error", err)
			}
		}
	}()

	for _, host := range hosts {
		hostChan <- host
	}
	close(hostChan)

	wg.Wait()
	close(resultChan)
	resultsWg.Wait()
}

type Output struct {
	Host     string           `json:"host"`
	TCPPorts map[string]State `json:"tcp"`
	UDPPorts map[string]State `json:"udp"`
}

type State struct {
	State string `json:"state"`
}
