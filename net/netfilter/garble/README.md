# garble module usage

`garble` is a Netfilter helper module that injects short fake TCP/UDP payloads
around selected flows. Runtime configuration is exposed through sysctl under:

```sh
/proc/sys/net/garble/
```

Custom binary payloads and counters are exposed through:

```sh
/proc/garble/tcp_payload
/proc/garble/udp_payload
/proc/garble/tcp/payload_file/
/proc/garble/udp/payload_file/
/proc/garble/stats
```

## Basic switches

Common sysctl knobs:

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
tcp_repeat_pkt=3
udp_repeat_pkt=1
tcp_ttl=3
udp_ttl=3
tcp_obf_proto=
udp_obf_proto=
domains=
lan_nics=br-virt,br-vmbr0
```

`tcp_ttl` and `udp_ttl` accept values from `3` to `128`.

## TCP obfuscation profiles

`tcp_obf_proto` accepts a comma-separated list of protocol names or numeric
IDs. An empty value disables this configurable TCP profile set.

Supported TCP profiles:

| ID | Name | Payload shape |
| -- | -- | -- |
| 0 | `http` | HTTP request |
| 1 | `tls` / `tls_clienthello` | TLS ClientHello |
| 2 | `ssh` / `ssh_banner` | SSH client banner |
| 3 | `rtmp` / `rtmp_handshake` | RTMP C0/C1-like handshake |
| 4 | `postgres` / `postgres_startup` | PostgreSQL startup packet |
| 5 | `mqtt` / `mqtt_connect` | MQTT CONNECT |
| 6 | `ftp` / `ftp_user` | FTP `USER ...\r\n` command |
| 7 | `payload_file` / `file` | Random payload file under `/proc/garble/tcp/payload_file/` |

Examples:

```sh
sysctl -w net.garble.tcp_obf_proto=ssh
sysctl -w net.garble.tcp_obf_proto=0,2,5
sysctl -w net.garble.tcp_obf_proto=tls,ssh,mqtt,ftp
sysctl -w net.garble.tcp_obf_proto=payload_file
sysctl -w net.garble.tcp_obf_proto=
```

When a valid value is written, the kernel log prints the resolved profile set,
for example:

```text
garble: tcp_obf_proto updated to 0,2,6 [http(0),ssh_banner(2),ftp_user(6)]
```

### TCP selection priority

TCP payload selection currently follows this order:

1. `enable_tcp_binary_payload=1`: use `/proc/garble/tcp_payload`.
2. `enable=1` and `enable_http=1`: randomly choose legacy TLS or HTTP.
3. `enable=1`: use legacy TLS ClientHello.
4. `enable_http=1`: use legacy HTTP request.
5. non-empty `tcp_obf_proto`: randomly choose from the configured profile set.

So if `enable=1` or `enable_http=1` is set, it takes precedence over
`tcp_obf_proto`.

## UDP obfuscation profiles

`udp_obf_proto` also accepts a comma-separated list of names or numeric IDs.
An empty value disables the configurable UDP profile set. `enable_udp=1` is
still the UDP master switch.

Supported UDP profiles:

| ID | Name |
| -- | -- |
| 0 | `turn` / `turn_allocate` |
| 1 | `wechat` / `wechat_video` |
| 2 | `sip` / `sip_invite` |
| 3 | `dtls` / `dtls_clienthello` |
| 4 | `turn_create_permission` |
| 5 | `turn_allocate_error_response` |
| 6 | `turn_channel_bind` |
| 7 | `tftp` / `tftp_rrq` |
| 8 | `wechat_video_new` |
| 9 | `xiaomi` / `xiaomi_camera` |
| 10 | `bilibili` / `bilibili_live` |
| 11 | `payload_file` / `file` |

Examples:

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=10
sysctl -w net.garble.udp_obf_proto=0,3,10
sysctl -w net.garble.udp_obf_proto=turn_allocate,dtls,bilibili_live
sysctl -w net.garble.udp_obf_proto=payload_file
sysctl -w net.garble.udp_obf_proto=
```

Successful writes are logged with resolved names:

```text
garble: udp_obf_proto updated to 0,3,10 [turn_allocate(0),dtls_clienthello(3),bilibili_live(10)]
```

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

The payload size is limited by the module's `GARBLE_MAX_TCP_PAYLOAD` and
`GARBLE_MAX_UDP_PAYLOAD`.

## Payload file profiles

`payload_file` is a generated profile selectable through `tcp_obf_proto` or
`udp_obf_proto`. When this profile is selected, garble randomly picks one
non-empty managed file from the corresponding procfs directory and uses its
content as the fake packet payload.

Payload file directories:

```sh
/proc/garble/tcp/payload_file/
/proc/garble/udp/payload_file/
```

Each directory contains a control file named `ctl`. Use `ctl` to create or
delete managed payload files:

```sh
echo 'create p1' > /proc/garble/tcp/payload_file/ctl
printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > /proc/garble/tcp/payload_file/p1
cat /proc/garble/tcp/payload_file/p1
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

Enable TCP payload-file selection:

```sh
sysctl -w net.garble.tcp_obf_proto=payload_file
```

Enable UDP payload-file selection:

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=payload_file
```

The `ctl` file is not part of the random payload pool. Only files created
through `ctl` and containing a non-empty payload can be selected. TCP files are
limited by `GARBLE_MAX_TCP_PAYLOAD`; UDP files are limited by
`GARBLE_MAX_UDP_PAYLOAD`.

## Domains

`domains` is a comma-separated list used by generated HTTP/TLS/DTLS payloads
as hostnames or SNI values.

```sh
sysctl -w net.garble.domains=example.com,www.example.com
```

If a selected profile needs a domain but no domain is configured, payload
generation may fail and no fake packet is sent.

## Common examples

Enable TCP configurable profiles only:

```sh
sysctl -w net.garble.domains=example.com
sysctl -w net.garble.tcp_obf_proto=tls,ssh,ftp
sysctl -w net.garble.tcp_repeat_pkt=3
```

Enable UDP Bilibili-live style UDT handshake:

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=bilibili_live
sysctl -w net.garble.udp_repeat_pkt=1
```

Enable mixed UDP profile selection:

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=turn_allocate,dtls,bilibili_live
```

Check counters:

```sh
cat /proc/garble/stats
```

## Notes

- `tcp_obf_proto` and `udp_obf_proto` are parsed into RCU-backed masks, so
  packet-path reads do not directly parse sysctl strings.
- Invalid profile names or IDs are rejected and do not replace the active
  profile set.
- Empty `tcp_obf_proto` or `udp_obf_proto` means the corresponding configurable
  profile set is disabled.
- UDP still requires `enable_udp=1`; TCP configurable profiles do not have a
  separate `enable_tcp` switch.
