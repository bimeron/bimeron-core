module bimeron

go 1.26.9

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6
	github.com/xjasonlyu/tun2socks/v2 v2.6.0
	golang.org/x/net v0.61.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20250523182742-eede7a881b20
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	go4.org/netipx v0.0.0-20220725152314-7e7bdc8411bf // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

require (
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	golang.getoutline.org/sdk v0.0.21
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0
)

replace github.com/tailscale/wf => ./third_party/wf

tool golang.org/x/mobile/cmd/gobind
