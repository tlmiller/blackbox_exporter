// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"html"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/handler"
	"github.com/prometheus/blackbox_exporter/result"
)

var (
	sc = &config.SafeConfig{
		C: &config.Config{},
	}

	configFile    = kingpin.Flag("config.file", "Blackbox exporter configuration file.").Default("blackbox.yml").String()
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":9115").String()
	timeoutOffset = kingpin.Flag("timeout-offset", "Offset to subtract from timeout in seconds.").Default("0.5").Float64()
	configCheck   = kingpin.Flag("config.check", "If true validate the config file and then exit.").Default().Bool()
	historyLimit  = kingpin.Flag("history.limit", "The maximum amount of items to keep in the history.").Default("100").Uint()
)

func init() {
	prometheus.MustRegister(version.NewCollector("blackbox_exporter"))
}

func main() {
	allowedLevel := promlog.AllowedLevel{}
	flag.AddFlags(kingpin.CommandLine, &allowedLevel)
	kingpin.Version(version.Print("blackbox_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(allowedLevel)
	rh := &result.ResultHistory{MaxResults: *historyLimit}

	level.Info(logger).Log("msg", "Starting blackbox_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", version.BuildContext())

	if err := sc.ReloadConfigFromFile(*configFile); err != nil {
		level.Error(logger).Log("msg", "Error loading config", "err", err)
		os.Exit(1)
	}

	if *configCheck {
		level.Info(logger).Log("msg", "Config file is ok exiting...")
		os.Exit(0)
	}

	level.Info(logger).Log("msg", "Loaded config file")

	hup := make(chan os.Signal, 1)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfigFromFile(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					continue
				}
				level.Info(logger).Log("msg", "Reloaded config file")
			case rc := <-reloadCh:
				if err := sc.ReloadConfigFromFile(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Reloaded config file")
					rc <- nil
				}
			}
		}
	}()

	http.HandleFunc("/-/reload",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprintf(w, "This endpoint requires a POST request.\n")
				return
			}

			rc := make(chan error)
			reloadCh <- rc
			if err := <-rc; err != nil {
				http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
			}
		})
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		sc.Lock()
		conf := sc.C
		sc.Unlock()
		handler.Probe(w, r, conf, logger, rh)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
    <head><title>Blackbox Exporter</title></head>
    <body>
    <h1>Blackbox Exporter</h1>
    <p><a href="/probe?target=prometheus.io&module=http_2xx">Probe prometheus.io for http_2xx</a></p>
    <p><a href="/probe?target=prometheus.io&module=http_2xx&debug=true">Debug probe prometheus.io for http_2xx</a></p>
    <p><a href="/metrics">Metrics</a></p>
    <p><a href="/config">Configuration</a></p>
    <h2>Recent Probes</h2>
    <table border='1'><tr><th>Module</th><th>Target</th><th>Result</th><th>Debug</th>`))

		results := rh.List()

		for i := len(results) - 1; i >= 0; i-- {
			r := results[i]
			success := "Success"
			if !r.Success {
				success = "<strong>Failure</strong>"
			}
			fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td><a href='logs?id=%d'>Logs</a></td></td>",
				html.EscapeString(r.ModuleName), html.EscapeString(r.Target), success, r.Id)
		}

		w.Write([]byte(`</table></body>
    </html>`))
	})

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil {
			http.Error(w, "Invalid probe id", 500)
			return
		}
		result := rh.Get(id)
		if result == nil {
			http.Error(w, "Probe id not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(result.DebugOutput))
	})

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		sc.RLock()
		c, err := yaml.Marshal(sc.C)
		sc.RUnlock()
		if err != nil {
			level.Warn(logger).Log("msg", "Error marshalling configuration", "err", err)
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(c)
	})

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
