module kevaso.com/core

go 1.27

toolchain go1.27.4

require (
	cel.dev/cel-go v0.33.2
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/hashicorp/yamux v0.1.2
	github.com/miekg/dns v1.1.68
	github.com/vishvananda/netlink v1.3.1
	go.yaml.in/yaml/v3 v3.0.6
	golang.org/x/crypto v0.59.0
	golang.org/x/oauth2 v0.38.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.48.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	kevaso.com/core/api v0.0.0-00010101000000-000000000000
	kevaso.com/core/sdk v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.62.0
)

require (
	cel.dev/expr v0.25.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

replace kevaso.com/core/api => ./api

replace kevaso.com/core/sdk => ./sdk
