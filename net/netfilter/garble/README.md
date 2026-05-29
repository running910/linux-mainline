# garble module usage

`garble` is a Netfilter helper module that injects short fake TCP/UDP
payloads around selected flows. The module is configured at runtime through
sysctl:

```sh
/proc/sys/net/garble/
```

Additional procfs entries expose custom payload buffers, managed payload-file
pools, protocol IDs, and counters:

```sh
/proc/garble/tcp_payload
/proc/garble/udp_payload
/proc/garble/tcp/payload_file/
/proc/garble/udp/payload_file/
/proc/garble/stats
/proc/garble/protos
```

## Sysctl knobs

Common knobs and defaults:

```sh
enable=0
enable_http=0
enable_udp=0
enable_tcp_client=0
enable_local_obf=0
enable_wellknown_port_obf=0
enable_routing=0
enable_tcp_aggressive=0
enable_udp_aggressive=0
enable_tcp_binary_payload=0
enable_udp_binary_payload=0
tcp_aggr_avg_pkt=0
udp_aggr_avg_pkt=0
tcp_repeat_pkt=3
udp_repeat_pkt=1
tcp_ttl=3
udp_ttl=3
ttl_percent=0
tcp_obf_proto=
udp_obf_proto=
udp_extra=
domains=
domains_tls=
lan_nics=br-virt,br-vmbr0
```

`tcp_ttl` and `udp_ttl` accept `3..128`. `ttl_percent` accepts `0..99`; `0`
disables dynamic TTL adjustment. When enabled, garble estimates the peer hop
count from the original packet TTL or IPv6 hop limit:

```text
final_ttl = max(tcp_ttl or udp_ttl, estimated_hops * ttl_percent / 100)
```

For example, `tcp_ttl=3` and `ttl_percent=50` produce TTL `10` for a peer
estimated to be 20 hops away.

## Protocol selection and weights

`tcp_obf_proto` and `udp_obf_proto` accept comma-separated protocol names or
numeric IDs. They also support weights with a fixed total granularity of
`1000`.

Examples:

```sh
# Equal split: 250 each.
sysctl -w net.garble.tcp_obf_proto=tls,ssh,mqtt,ftp

# tls gets 500; ssh/mqtt/ftp split the remaining 500.
sysctl -w net.garble.tcp_obf_proto=tls=500,ssh,mqtt,ftp

# Valid only when all explicit weights sum to 1000.
sysctl -w net.garble.tcp_obf_proto=tls=500,ssh=200
```

The last example is rejected because all listed protocols have explicit weights
and the total is only `700`. Rules:

- Empty value disables the configurable profile set.
- Unknown names, invalid IDs, duplicates, and non-positive weights are rejected.
- If every listed profile has an explicit weight, the sum must be exactly
  `1000`.
- If some listed profiles omit weights, the remainder is split across them.

Successful writes are logged with the resolved weights, for example:

```text
garble: tcp_obf_proto updated to tls=500,ssh,mqtt,ftp [tls_clienthello(1)=500,ssh_banner(2)=167,mqtt_connect(5)=167,ftp_user(6)=166]
```

Use `/proc/garble/protos` to inspect the compiled protocol names and IDs.

## TCP obfuscation profiles

Supported TCP profiles:

| ID | Name | Payload shape |
| -- | -- | -- |
| 0 | `http` | HTTP request with randomized method/path/User-Agent |
| 1 | `tls` / `tls_clienthello` | TLS ClientHello |
| 2 | `ssh` / `ssh_banner` | SSH client banner |
| 3 | `rtmp` / `rtmp_handshake` | RTMP C0/C1-like handshake |
| 4 | `postgres` / `postgres_startup` | PostgreSQL startup packet |
| 5 | `mqtt` / `mqtt_connect` | MQTT CONNECT |
| 6 | `ftp` / `ftp_user` | FTP `USER ...\r\n` command |
| 7 | `payload_file` / `file` | Random file from `/proc/garble/tcp/payload_file/` |
| 8 | `vnc` | VNC/RFB version banner |
| 9 | `thrift` / `thrift_call` | Thrift binary protocol CALL |
| 10 | `sip` / `sip_invite` | SIP INVITE over TCP |
| 11 | `http_search_tieba` / `search_tieba` | HTTP search request template |
| 12 | `http_search_c_tieba` / `search_c_tieba` | HTTP search request template |
| 13 | `http_search_deepseek_scholar` / `search_deepseek_scholar` | HTTP search request template |
| 14 | `http_search_deepseek_kns` / `search_deepseek_kns` | HTTP search request template |
| 15 | `http_search_icourse163` / `search_icourse163` | HTTP search request template |
| 16 | `http_search_mooc_study_163` / `search_mooc_study_163` | HTTP search request template |
| 17 | `http_search_ke_qq` / `search_ke_qq` | HTTP search request template |
| 18 | `http_search_h5_ke_qq` / `search_h5_ke_qq` | HTTP search request template |
| 19 | `http_search_xhs_www` / `search_xhs_www` | HTTP search request template |
| 20 | `http_search_xhs_api` / `search_xhs_api` | HTTP search request template |
| 21 | `http_search_xhs_creator` / `search_xhs_creator` | HTTP search request template |
| 22 | `http_search_ximalaya_mobile` / `search_ximalaya_mobile` | HTTP search request template |
| 23 | `http_search_ximalaya_api` / `search_ximalaya_api` | HTTP search request template |
| 24 | `http_search_open_163` / `search_open_163` | HTTP search request template |
| 25 | `http_search_vod_open_163` / `search_vod_open_163` | HTTP search request template |
| 26 | `http_search_imooc` / `search_imooc` | HTTP search request template |
| 27 | `http_search_coding_imooc` / `search_coding_imooc` | HTTP search request template |
| 28 | `http_download` / `download` | HTTP download request |
| 29 | `tlsv1` / `tlsv1_clienthello` | TLS 1.0-style ClientHello |

Examples:

```sh
sysctl -w net.garble.domains=example.com,www.example.com
sysctl -w net.garble.domains_tls=tls.example.com,www.example.com
sysctl -w net.garble.tcp_obf_proto=tls=400,http=300,sip=200,ssh=100
sysctl -w net.garble.tcp_obf_proto=http_search_tieba,http_download,tlsv1
sysctl -w net.garble.tcp_repeat_pkt=3
```

### TCP selection priority

TCP payload selection follows this order:

1. `enable_tcp_binary_payload=1`: use `/proc/garble/tcp_payload`.
2. `enable=1` and `enable_http=1`: randomly choose legacy TLS or HTTP.
3. `enable=1`: use legacy TLS ClientHello.
4. `enable_http=1`: use legacy HTTP request.
5. non-empty `tcp_obf_proto`: choose by configured TCP weights.

If `enable` or `enable_http` is set, it takes precedence over
`tcp_obf_proto`.

## UDP obfuscation profiles

`udp_obf_proto` uses the same weighted syntax. `enable_udp=1` is still the UDP
master switch.

Supported UDP profiles:

| ID | Name | Payload shape |
| -- | -- | -- |
| 0 | `turn` / `turn_allocate` | TURN Allocate |
| 1 | `wechat` / `wechat_video` | WeChat video-like payload |
| 2 | `sip` / `sip_invite` | SIP INVITE over UDP |
| 3 | `dtls` / `dtls_clienthello` | DTLS ClientHello |
| 4 | `turn_create_permission` | TURN CreatePermission |
| 5 | `turn_allocate_error_response` | TURN Allocate error response |
| 6 | `turn_channel_bind` | TURN ChannelBind |
| 7 | `tftp` / `tftp_rrq` | TFTP RRQ |
| 8 | `wechat_video_new` | Newer WeChat video-like payload |
| 9 | `xiaomi` / `xiaomi_camera` | Xiaomi camera-like handshake |
| 10 | `bilibili` / `bilibili_live` | Bilibili-live style UDT handshake |
| 11 | `payload_file` / `file` | Random file from `/proc/garble/udp/payload_file/` |

Examples:

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=sip=400,dtls=300,turn=300
sysctl -w net.garble.udp_obf_proto=turn_allocate,dtls,bilibili_live
sysctl -w net.garble.udp_repeat_pkt=1
```

`udp_extra` is used by some UDP payload builders. For SIP, if `udp_extra` is
set, it is used as the SIP URI host; otherwise the real destination address is
used.

## SIP and realistic identities

SIP INVITE payloads are available for both TCP and UDP. When tuple information
is available, garble uses the real source address in `Via`, `From`,
`Call-ID`, `Contact`, and SDP `o=`/`c=` lines. The request URI and `To` header
use the configured `udp_extra` host when present, otherwise the real
destination address.

SIP usernames are realistic by default: 90% are generated by `get_email_name()`
using common pinyin-name, birth-year, job, interest, and separator patterns;
10% fall back to short random alphanumeric names. `get_email()` additionally
combines those names with a pool of common real-world mail domains for callers
that need a full address.

## Custom binary payloads

Binary payload mode overrides generated protocol payloads.

TCP:

```sh
printf 'hello\r\n' > /proc/garble/tcp_payload
sysctl -w net.garble.enable_tcp_binary_payload=1
```

UDP:

```sh
printf 'hello' > /proc/garble/udp_payload
sysctl -w net.garble.enable_udp_binary_payload=1
```

The payload size is limited by `GARBLE_MAX_TCP_PAYLOAD` and
`GARBLE_MAX_UDP_PAYLOAD`.

## Payload file profiles

The `payload_file` profile randomly picks one non-empty managed file from the
corresponding procfs directory:

```sh
/proc/garble/tcp/payload_file/
/proc/garble/udp/payload_file/
```

Create, inspect, and delete files through `ctl`:

```sh
echo 'create p1' > /proc/garble/tcp/payload_file/ctl
printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > /proc/garble/tcp/payload_file/p1
cat /proc/garble/tcp/payload_file/ctl
echo 'delete p1' > /proc/garble/tcp/payload_file/ctl
```

UDP uses the same workflow:

```sh
echo 'create u1' > /proc/garble/udp/payload_file/ctl
printf 'hello' > /proc/garble/udp/payload_file/u1
cat /proc/garble/udp/payload_file/ctl
echo 'delete u1' > /proc/garble/udp/payload_file/ctl
```

The `ctl` file is not part of the random pool. Only files created through
`ctl` and containing non-empty payloads can be selected.

## Domains

`domains` is a comma-separated list used by generated HTTP, HTTP download, and
DTLS payloads as hostnames or SNI values.

`domains_tls` is a separate comma-separated list used by TCP TLS payloads:
`tls` / `tls_clienthello` and `tlsv1` / `tlsv1_clienthello`.

```sh
sysctl -w net.garble.domains=example.com,www.example.com
sysctl -w net.garble.domains_tls=tls.example.com,www.example.com
```

Profiles that require a domain fail payload generation when no domain is
configured. TLS profiles require `domains_tls`; HTTP and DTLS profiles require
`domains`.

## Counters and diagnostics

Counters:

```sh
cat /proc/garble/stats
```

Available profile IDs:

```sh
cat /proc/garble/protos
```

Kernel logs print selected profiles and resolved weight sets when protocol
configuration changes.

## Common examples

Weighted TCP mix:

```sh
sysctl -w net.garble.domains=example.com
sysctl -w net.garble.domains_tls=tls.example.com
sysctl -w net.garble.tcp_obf_proto=tls=350,http=250,sip=200,ssh,mqtt
sysctl -w net.garble.tcp_repeat_pkt=3
```

HTTP-search style traffic:

```sh
sysctl -w net.garble.tcp_obf_proto=http_search_tieba,http_search_imooc,http_download
```

UDP SIP/DTLS/TURN mix:

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=sip=400,dtls=300,turn=300
```

Payload-file based TCP:

```sh
echo 'create p1' > /proc/garble/tcp/payload_file/ctl
printf 'custom payload' > /proc/garble/tcp/payload_file/p1
sysctl -w net.garble.tcp_obf_proto=payload_file
```

## Notes

- `tcp_obf_proto` and `udp_obf_proto` are parsed into RCU-backed weight
  configs, so packet-path reads do not parse sysctl strings.
- Invalid profile configs are rejected and do not replace the active config.
- Empty `tcp_obf_proto` or `udp_obf_proto` disables the corresponding
  configurable profile set.
- UDP requires `enable_udp=1`; TCP configurable profiles do not have a separate
  master switch.
