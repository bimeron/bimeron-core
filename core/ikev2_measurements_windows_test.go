//go:build windows

package core

import (
	"bimeron/internal/systemvpn"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ikev2Measurement struct {
	Mode            string             `json:"mode"`
	ConnectMS       []float64          `json:"connect_ms"`
	StopMS          []float64          `json:"stop_ms"`
	Transfers       []json.RawMessage  `json:"iperf,omitempty"`
	Idle            map[string]float64 `json:"idle"`
	DataReadyMS     float64            `json:"data_ready_ms"`
	ReadinessErrors []string           `json:"readiness_errors,omitempty"`
}

func measurementCounters() (map[string]float64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		return nil, err
	}
	ticks := func(f windows.Filetime) float64 {
		return float64(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) / 1e7
	}
	var idle, systemKernel, systemUser windows.Filetime
	code, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemTimes").Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&systemKernel)), uintptr(unsafe.Pointer(&systemUser)))
	if code == 0 {
		return nil, fmt.Errorf("system CPU counters unavailable")
	}
	var memory struct {
		Size, PageFaults                                                                                             uint32
		PeakWorkingSet, WorkingSet, PeakPagedPool, PagedPool, PeakNonPagedPool, NonPagedPool, Pagefile, PeakPagefile uintptr
	}
	memory.Size = uint32(unsafe.Sizeof(memory))
	code, _, _ = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&memory)), uintptr(memory.Size))
	if code == 0 {
		return nil, fmt.Errorf("process memory unavailable")
	}
	var heap runtime.MemStats
	runtime.ReadMemStats(&heap)
	return map[string]float64{"process_cpu_s": ticks(kernel) + ticks(user), "system_busy_s": ticks(systemKernel) + ticks(systemUser) - ticks(idle), "system_total_s": ticks(systemKernel) + ticks(systemUser), "working_set_bytes": float64(memory.WorkingSet), "go_heap_bytes": float64(heap.HeapAlloc)}, nil
}

// Run only on a disposable interactive Windows VPN machine. This measures the
// same saved profile through native RAS, Engine and protected Engine, then holds
// the protected connection while probing controlled IPv4/IPv6/DNS endpoints.
func TestWindowsIKEv2Measurements(t *testing.T) {
	output := os.Getenv("BIMERON_IKEV2_MEASURE_OUTPUT")
	if output == "" {
		t.Skip("requires explicit isolated measurement opt-in")
	}
	cfg, err := LoadConfig(os.Getenv("BIMERON_IKEV2_TEST_CONFIG"))
	if err != nil || cfg.IKEv2 == nil {
		t.Fatal("measurement requires a native IKEv2 config", err)
	}
	iperf := os.Getenv("BIMERON_IKEV2_IPERF")
	if iperf == "" {
		t.Fatal("set BIMERON_IKEV2_IPERF to a trusted iperf3 executable")
	}
	seconds, err := strconv.Atoi(os.Getenv("BIMERON_IKEV2_SOAK_SECONDS"))
	if err != nil || seconds < 60 {
		t.Fatal("set BIMERON_IKEV2_SOAK_SECONDS to at least 60")
	}
	address := os.Getenv("BIMERON_IKEV2_PROBE_ADDRESS")
	address6 := os.Getenv("BIMERON_IKEV2_PROBE_ADDRESS6")
	dnsName := os.Getenv("BIMERON_IKEV2_PROBE_DNS")
	if net.ParseIP(address) == nil || net.ParseIP(address6) == nil || dnsName == "" {
		t.Fatal("set controlled IPv4/IPv6 probe addresses and DNS name")
	}
	report := map[string]any{"started": time.Now().UTC(), "measurements": []*ikev2Measurement{}, "soak": []map[string]any{}}
	write := func() {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { report["finished"] = time.Now().UTC(); report["success"] = !t.Failed(); write() }()
	probeClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	probe := func() (map[string]any, error) {
		row := map[string]any{"time": time.Now().UTC()}
		for _, ip := range []string{address, address6} {
			start := time.Now()
			response, err := probeClient.Get("http://" + net.JoinHostPort(ip, "8080") + "/health")
			if err != nil {
				return row, err
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if readErr != nil || response.StatusCode != 200 {
				return row, fmt.Errorf("HTTP probe failed for %s", ip)
			}
			row[ip+"_http_ms"] = float64(time.Since(start).Microseconds()) / 1000
		}
		return row, nil
	}
	connect := func(mode string) (func() error, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+600)*time.Second)
		if mode == "native" {
			session, err := systemvpn.Open(ctx, systemvpn.Config{WindowsProfile: cfg.IKEv2.WindowsProfile, ServerName: cfg.IKEv2.ServerName})
			if err != nil {
				cancel()
				return nil, err
			}
			return func() error { defer cancel(); return session.Close() }, nil
		}
		settings := *cfg.IKEv2
		settings.KillSwitch = mode == "protected"
		current := cfg
		current.IKEv2 = &settings
		engine := New(Options{})
		stop := func() error {
			defer cancel()
			end, finish := context.WithTimeout(context.Background(), 45*time.Second)
			defer finish()
			return engine.Stop(end)
		}
		if err := engine.Start(ctx, current); err != nil {
			_ = stop()
			return nil, err
		}
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			status := engine.Status()
			if status.State == Connected {
				return stop, nil
			}
			if status.State == Failed {
				_ = stop()
				return nil, fmt.Errorf("%s", status.LastError)
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = stop()
		return nil, fmt.Errorf("connection timed out")
	}
	for _, mode := range []string{"native", "engine", "protected"} {
		measurement := &ikev2Measurement{Mode: mode}
		report["measurements"] = append(report["measurements"].([]*ikev2Measurement), measurement)
		for cycle := 0; cycle < 20; cycle++ {
			start := time.Now()
			stop, err := connect(mode)
			if err != nil {
				t.Fatal(mode, cycle, err)
			}
			measurement.ConnectMS = append(measurement.ConnectMS, float64(time.Since(start).Microseconds())/1000)
			start = time.Now()
			err = stop()
			measurement.StopMS = append(measurement.StopMS, float64(time.Since(start).Microseconds())/1000)
			if err != nil {
				t.Fatal(mode, cycle, err)
			}
			write()
		}
		func() {
			stop, err := connect(mode)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := stop(); err != nil {
					t.Error(err)
				}
			}()
			// RAS readiness can precede the data plane. Record retries separately;
			// a fixed sleep is not evidence of address/route readiness.
			readyStart := time.Now()
			for {
				if _, err := probe(); err == nil {
					break
				} else {
					measurement.ReadinessErrors = append(measurement.ReadinessErrors, err.Error())
					if time.Since(readyStart) > 45*time.Second {
						t.Fatal("data plane not ready", err)
					}
					time.Sleep(time.Second)
				}
			}
			measurement.DataReadyMS = float64(time.Since(readyStart).Microseconds()) / 1000
			before, err := measurementCounters()
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Second)
			after, err := measurementCounters()
			if err != nil {
				t.Fatal(err)
			}
			after["process_idle_cpu_s"] = after["process_cpu_s"] - before["process_cpu_s"]
			after["system_idle_busy_percent"] = 100 * (after["system_busy_s"] - before["system_busy_s"]) / (after["system_total_s"] - before["system_total_s"])
			measurement.Idle = after
			for _, protocol := range []string{"tcp-up", "tcp-down", "udp-up", "udp-down"} {
				args := []string{"-c", address, "-t", "10", "-b", "50M", "-J"}
				if protocol == "udp-up" || protocol == "udp-down" {
					args = append(args, "-u", "-l", "1200")
				}
				if protocol == "tcp-down" || protocol == "udp-down" {
					args = append(args, "-R")
				}
				before, err := measurementCounters()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				data, err := exec.CommandContext(ctx, iperf, args...).Output()
				cancel()
				if err != nil {
					t.Fatal("iperf", mode, protocol, err)
				}
				var transfer map[string]any
				if json.Unmarshal(data, &transfer) != nil || transfer["error"] != nil {
					t.Fatal("iperf returned an error")
				}
				after, err := measurementCounters()
				if err != nil {
					t.Fatal(err)
				}
				transfer["protocol"] = protocol
				transfer["bimeron_cpu_s"] = after["process_cpu_s"] - before["process_cpu_s"]
				transfer["system_busy_percent"] = 100 * (after["system_busy_s"] - before["system_busy_s"]) / (after["system_total_s"] - before["system_total_s"])
				encoded, _ := json.Marshal(transfer)
				measurement.Transfers = append(measurement.Transfers, encoded)
				write()
			}
		}()
		t.Log("completed cycle/throughput measurements:", mode)
	}
	stop, err := connect("protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	}()
	soakReadyStart := time.Now()
	for {
		if _, err := probe(); err == nil {
			break
		} else if time.Since(soakReadyStart) > 45*time.Second {
			t.Fatal("soak data plane not ready", err)
		}
		time.Sleep(time.Second)
	}
	report["soak_data_ready_ms"] = float64(time.Since(soakReadyStart).Microseconds()) / 1000
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		row, err := probe()
		if err != nil {
			t.Fatal("soak probe", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		answers, err := net.DefaultResolver.LookupIP(ctx, "ip", dnsName)
		cancel()
		if err != nil || len(answers) == 0 {
			t.Fatal("soak system DNS probe failed", err)
		}
		row["dns_answers"] = len(answers)
		row["resources"], err = measurementCounters()
		if err != nil {
			t.Fatal(err)
		}
		report["soak"] = append(report["soak"].([]map[string]any), row)
		write()
		time.Sleep(10 * time.Second)
	}
	report["soak_seconds"] = seconds
}
