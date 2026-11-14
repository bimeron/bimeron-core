//go:build darwin && cgo

// Package main builds the C archive embedded by the Apple packet provider.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"bimeron/core"
)

type instance struct {
	engine     *core.Engine
	port       *core.PacketPort
	config     core.SessionConfig
	generation atomic.Uint64
}

var instances = struct {
	sync.RWMutex
	next   uint64
	values map[uint64]*instance
}{values: make(map[uint64]*instance)}

func lookup(id C.ulonglong) *instance {
	instances.RLock()
	defer instances.RUnlock()
	return instances.values[uint64(id)]
}
func configBytes(data unsafe.Pointer, size C.int) []byte {
	if data == nil || size <= 0 || size > 65536 {
		return nil
	}
	return C.GoBytes(data, size)
}

//export RLCreate
func RLCreate(data unsafe.Pointer, size C.int) C.ulonglong {
	c, err := core.LoadConfigData(configBytes(data, size))
	return create(c, err)
}

func create(c core.SessionConfig, err error) C.ulonglong {
	if err != nil || core.ValidateEmbeddedHost(c) != nil {
		return 0
	}
	i := &instance{config: c}
	e, p, err := core.NewPacketEngine(core.Options{}, core.PacketOptions{MTU: c.MTU, Outbound: func(ctx context.Context) (core.PacketNetwork, error) {
		if err := ctx.Err(); err != nil {
			return core.PacketNetwork{}, err
		}
		return core.PacketNetwork{Identity: jsonNumber(i.generation.Load()), DNS: append([]string(nil), c.DNS...), Dialer: net.Dialer{Timeout: 15 * time.Second}}, nil
	}})
	if err != nil {
		return 0
	}
	i.engine, i.port = e, p
	instances.Lock()
	defer instances.Unlock()
	instances.next++
	instances.values[instances.next] = i
	return C.ulonglong(instances.next)
}
func jsonNumber(v uint64) string { b, _ := json.Marshal(v); return string(b) }

//export RLStart
func RLStart(id C.ulonglong) C.int {
	i := lookup(id)
	if i == nil {
		return -1
	}
	if i.engine.Start(context.Background(), i.config) != nil {
		return -1
	}
	return 0
}

//export RLWritePacket
func RLWritePacket(id C.ulonglong, data unsafe.Pointer, size C.int) C.int {
	i := lookup(id)
	if i == nil {
		return -1
	}
	if i.port.WritePacket(configBytes(data, size)) != nil {
		return -1
	}
	return 0
}

//export RLReadPacket
func RLReadPacket(id C.ulonglong, out unsafe.Pointer, capacity C.int, timeout C.int) C.int {
	i := lookup(id)
	if i == nil || out == nil || capacity < 65535 || capacity > 65536 || timeout < 1 || timeout > 1000 {
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	p, err := i.port.ReadPacket(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		return -1
	}
	copy(unsafe.Slice((*byte)(out), int(capacity)), p)
	return C.int(len(p))
}

//export RLStatus
func RLStatus(id C.ulonglong) *C.char {
	i := lookup(id)
	if i == nil {
		return nil
	}
	b, _ := json.Marshal(struct {
		Status core.Status `json:"status"`
		Stats  any         `json:"stats"`
	}{i.engine.Status(), i.engine.Stats()})
	return C.CString(string(b))
}

//export RLNetworkChanged
func RLNetworkChanged(id C.ulonglong) {
	if i := lookup(id); i != nil {
		i.generation.Add(1)
	}
}

//export RLVersion
func RLVersion() *C.char { b, _ := json.Marshal(core.GetBuildInfo()); return C.CString(string(b)) }

//export RLEvents
func RLEvents(id C.ulonglong) *C.char {
	i := lookup(id)
	if i == nil {
		return nil
	}
	events := make([]core.Event, 0, 8)
	for len(events) < 8 {
		select {
		case event := <-i.engine.Events():
			events = append(events, event)
		default:
			b, _ := json.Marshal(events)
			return C.CString(string(b))
		}
	}
	b, _ := json.Marshal(events)
	return C.CString(string(b))
}

//export RLSettings
func RLSettings(id C.ulonglong) *C.char {
	i := lookup(id)
	if i == nil {
		return nil
	}
	b, _ := json.Marshal(struct {
		MTU         int  `json:"mtu"`
		DisableIPv6 bool `json:"disable_ipv6"`
	}{i.config.MTU, i.config.DisableIPv6})
	return C.CString(string(b))
}

//export RLStop
func RLStop(id C.ulonglong) C.int {
	i := lookup(id)
	if i == nil {
		return 0
	}
	i.port.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if i.engine.Stop(ctx) != nil {
		return -1
	}
	instances.Lock()
	delete(instances.values, uint64(id))
	instances.Unlock()
	return 0
}

//export RLFree
func RLFree(ptr unsafe.Pointer) { C.free(ptr) }
func main()                     {}

// geoDataBytes checks bounds before crossing the C allocation boundary.
func geoDataBytes(data unsafe.Pointer, size C.int) ([]byte, error) {
	if size < 0 || size > 64*1024*1024 || (data == nil && size != 0) {
		return nil, errors.New("invalid dataset pointer or size (maximum 64 MiB)")
	}
	if size == 0 {
		return nil, nil
	}
	return C.GoBytes(data, size), nil
}

func loadGeoConfig(data unsafe.Pointer, size C.int, geoIP unsafe.Pointer, geoIPSize C.int, geoSite unsafe.Pointer, geoSiteSize C.int) (core.SessionConfig, error) {
	ip, err := geoDataBytes(geoIP, geoIPSize)
	if err != nil {
		return core.SessionConfig{}, err
	}
	site, err := geoDataBytes(geoSite, geoSiteSize)
	if err != nil {
		return core.SessionConfig{}, err
	}
	profile := configBytes(data, size)
	return core.LoadConfigDataWithGeoData(profile, ip, site)
}

//export RLCreateWithGeoData
func RLCreateWithGeoData(data unsafe.Pointer, size C.int, geoIP unsafe.Pointer, geoIPSize C.int, geoSite unsafe.Pointer, geoSiteSize C.int) C.ulonglong {
	c, err := loadGeoConfig(data, size, geoIP, geoIPSize, geoSite, geoSiteSize)
	return create(c, err)
}

func geoDataJSON(groups []string, err error) *C.char {
	var message *string
	if err != nil {
		value := err.Error()
		message = &value
	}
	var details *core.GeoDataError
	errors.As(err, &details)
	b, _ := json.Marshal(struct {
		Groups   []string           `json:"groups"`
		Error    *string            `json:"error"`
		Details  *core.GeoDataError `json:"details,omitempty"`
		Problems []*core.Problem    `json:"problems,omitempty"`
	}{groups, message, details, problems(err)})
	return C.CString(string(b))
}

// RLErrorCatalog returns the JSON error catalog. Free the result with RLFree.
//
//export RLErrorCatalog
func RLErrorCatalog() *C.char {
	b, _ := core.ErrorCatalog()
	return C.CString(string(b))
}

//export RLGeoDataGroups
func RLGeoDataGroups(kind *C.char, data unsafe.Pointer, size C.int) *C.char {
	groups := []string{}
	bytes, err := geoDataBytes(data, size)
	if err == nil && kind == nil {
		err = errors.New("dataset kind required")
	}
	if err == nil {
		groups, err = core.GeoDataGroups(C.GoString(kind), bytes)
	}
	if groups == nil {
		groups = []string{}
	}
	return geoDataJSON(groups, err)
}

//export RLValidateConfigWithGeoData
func RLValidateConfigWithGeoData(data unsafe.Pointer, size C.int, geoIP unsafe.Pointer, geoIPSize C.int, geoSite unsafe.Pointer, geoSiteSize C.int) *C.char {
	c, err := loadGeoConfig(data, size, geoIP, geoIPSize, geoSite, geoSiteSize)
	if err == nil {
		err = core.ValidateEmbeddedHost(c)
	}
	return geoDataJSON(nil, err)
}

//export RLCapabilities
func RLCapabilities() *C.char {
	c := core.PlatformCapabilities()
	c = core.Capabilities{Platform: "darwin", VPN: true, IPv4: true, IPv6: true, IPSplit: true, DomainSplit: true, GeoIPSplit: true, GeoSiteSplit: true, GeoDataSchema: c.GeoDataSchema, ExplicitAccess: c.ExplicitAccess}
	b, _ := json.Marshal(c)
	return C.CString(string(b))
}

// problems lists structured failures; success keeps the historical JSON
// without a problems field.
func problems(err error) []*core.Problem {
	if err == nil {
		return nil
	}
	return core.Problems(err)
}
