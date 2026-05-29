# garble 模块使用说明

`garble` 是一个 Netfilter 辅助模块，用于在选中的 TCP/UDP 连接附近注入短的伪造负载。运行时配置通过 sysctl 暴露：

```sh
/proc/sys/net/garble/
```

自定义负载、payload 文件池、协议 ID 和统计信息通过 procfs 暴露：

```sh
/proc/garble/tcp_payload
/proc/garble/udp_payload
/proc/garble/tcp/payload_file/
/proc/garble/udp/payload_file/
/proc/garble/stats
/proc/garble/protos
```

## Sysctl 配置项

常用配置项和默认值：

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

`tcp_ttl` 和 `udp_ttl` 取值范围是 `3..128`。`ttl_percent` 取值范围是 `0..99`，`0` 表示关闭动态 TTL 调整。启用后，模块会根据原始包 TTL 或 IPv6 hop limit 估算对端跳数：

```text
final_ttl = max(tcp_ttl 或 udp_ttl, estimated_hops * ttl_percent / 100)
```

例如 `tcp_ttl=3` 且 `ttl_percent=50` 时，如果估算对端距离是 20 跳，伪造 TCP 包会使用 TTL `10`。

## 协议选择和权重

`tcp_obf_proto` 和 `udp_obf_proto` 接受逗号分隔的协议名或数字 ID，也支持固定总粒度 `1000` 的权重配置。

示例：

```sh
# 均分：每个 250。
sysctl -w net.garble.tcp_obf_proto=tls,ssh,mqtt,ftp

# tls 权重 500，其余 ssh/mqtt/ftp 均分剩余 500。
sysctl -w net.garble.tcp_obf_proto=tls=500,ssh,mqtt,ftp

# 失败：所有协议都显式给了权重，但总和不是 1000。
sysctl -w net.garble.tcp_obf_proto=tls=500,ssh=200
```

规则：

- 空值表示关闭对应的可配置协议集合。
- 未知协议名、非法 ID、重复协议、非正权重都会被拒绝。
- 如果所有协议都显式设置权重，权重和必须正好等于 `1000`。
- 如果有协议没有设置权重，剩余权重会在这些协议之间分配。

写入成功后，内核日志会打印解析后的权重，例如：

```text
garble: tcp_obf_proto updated to tls=500,ssh,mqtt,ftp [tls_clienthello(1)=500,ssh_banner(2)=167,mqtt_connect(5)=167,ftp_user(6)=166]
```

可以通过 `/proc/garble/protos` 查看当前编译进去的协议 ID 和名称。

## TCP 混淆协议

当前支持的 TCP profile：

| ID | 名称 | 负载形态 |
| -- | -- | -- |
| 0 | `http` | HTTP 请求，随机 method/path/User-Agent |
| 1 | `tls` / `tls_clienthello` | TLS ClientHello |
| 2 | `ssh` / `ssh_banner` | SSH client banner |
| 3 | `rtmp` / `rtmp_handshake` | 类 RTMP C0/C1 握手 |
| 4 | `postgres` / `postgres_startup` | PostgreSQL startup packet |
| 5 | `mqtt` / `mqtt_connect` | MQTT CONNECT |
| 6 | `ftp` / `ftp_user` | FTP `USER ...\r\n` 命令 |
| 7 | `payload_file` / `file` | 从 `/proc/garble/tcp/payload_file/` 随机取文件 |
| 8 | `vnc` | VNC/RFB version banner |
| 9 | `thrift` / `thrift_call` | Thrift binary protocol CALL |
| 10 | `sip` / `sip_invite` | TCP 上的 SIP INVITE |
| 11 | `http_search_tieba` / `search_tieba` | HTTP 搜索请求模板 |
| 12 | `http_search_c_tieba` / `search_c_tieba` | HTTP 搜索请求模板 |
| 13 | `http_search_deepseek_scholar` / `search_deepseek_scholar` | HTTP 搜索请求模板 |
| 14 | `http_search_deepseek_kns` / `search_deepseek_kns` | HTTP 搜索请求模板 |
| 15 | `http_search_icourse163` / `search_icourse163` | HTTP 搜索请求模板 |
| 16 | `http_search_mooc_study_163` / `search_mooc_study_163` | HTTP 搜索请求模板 |
| 17 | `http_search_ke_qq` / `search_ke_qq` | HTTP 搜索请求模板 |
| 18 | `http_search_h5_ke_qq` / `search_h5_ke_qq` | HTTP 搜索请求模板 |
| 19 | `http_search_xhs_www` / `search_xhs_www` | HTTP 搜索请求模板 |
| 20 | `http_search_xhs_api` / `search_xhs_api` | HTTP 搜索请求模板 |
| 21 | `http_search_xhs_creator` / `search_xhs_creator` | HTTP 搜索请求模板 |
| 22 | `http_search_ximalaya_mobile` / `search_ximalaya_mobile` | HTTP 搜索请求模板 |
| 23 | `http_search_ximalaya_api` / `search_ximalaya_api` | HTTP 搜索请求模板 |
| 24 | `http_search_open_163` / `search_open_163` | HTTP 搜索请求模板 |
| 25 | `http_search_vod_open_163` / `search_vod_open_163` | HTTP 搜索请求模板 |
| 26 | `http_search_imooc` / `search_imooc` | HTTP 搜索请求模板 |
| 27 | `http_search_coding_imooc` / `search_coding_imooc` | HTTP 搜索请求模板 |
| 28 | `http_download` / `download` | HTTP 下载请求 |
| 29 | `tlsv1` / `tlsv1_clienthello` | TLS 1.0 风格 ClientHello |

示例：

```sh
sysctl -w net.garble.domains=example.com,www.example.com
sysctl -w net.garble.domains_tls=tls.example.com,www.example.com
sysctl -w net.garble.tcp_obf_proto=tls=400,http=300,sip=200,ssh=100
sysctl -w net.garble.tcp_obf_proto=http_search_tieba,http_download,tlsv1
sysctl -w net.garble.tcp_repeat_pkt=3
```

### TCP 选择优先级

TCP 负载选择顺序如下：

1. `enable_tcp_binary_payload=1`：使用 `/proc/garble/tcp_payload`。
2. `enable=1` 且 `enable_http=1`：旧逻辑中随机选择 TLS 或 HTTP。
3. `enable=1`：旧逻辑 TLS ClientHello。
4. `enable_http=1`：旧逻辑 HTTP 请求。
5. 非空 `tcp_obf_proto`：按 TCP 权重选择。

因此如果设置了 `enable` 或 `enable_http`，它们会优先于 `tcp_obf_proto`。

## UDP 混淆协议

`udp_obf_proto` 使用同样的权重语法。UDP 还需要总开关 `enable_udp=1`。

当前支持的 UDP profile：

| ID | 名称 | 负载形态 |
| -- | -- | -- |
| 0 | `turn` / `turn_allocate` | TURN Allocate |
| 1 | `wechat` / `wechat_video` | 类微信视频负载 |
| 2 | `sip` / `sip_invite` | UDP 上的 SIP INVITE |
| 3 | `dtls` / `dtls_clienthello` | DTLS ClientHello |
| 4 | `turn_create_permission` | TURN CreatePermission |
| 5 | `turn_allocate_error_response` | TURN Allocate error response |
| 6 | `turn_channel_bind` | TURN ChannelBind |
| 7 | `tftp` / `tftp_rrq` | TFTP RRQ |
| 8 | `wechat_video_new` | 新版类微信视频负载 |
| 9 | `xiaomi` / `xiaomi_camera` | 类小米摄像头握手 |
| 10 | `bilibili` / `bilibili_live` | 类 Bilibili 直播 UDT 握手 |
| 11 | `payload_file` / `file` | 从 `/proc/garble/udp/payload_file/` 随机取文件 |

示例：

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=sip=400,dtls=300,turn=300
sysctl -w net.garble.udp_obf_proto=turn_allocate,dtls,bilibili_live
sysctl -w net.garble.udp_repeat_pkt=1
```

`udp_extra` 会被部分 UDP 负载生成器使用。对 SIP 来说，如果设置了 `udp_extra`，它会作为 SIP URI 的 host；否则使用真实目的地址。

## SIP 和真实感身份

TCP 和 UDP 都支持 SIP INVITE。只要调用路径提供 tuple 信息，模块就会把真实源地址写入 `Via`、`From`、`Call-ID`、`Contact` 以及 SDP 的 `o=`/`c=` 行。Request URI 和 `To` 默认使用真实目的地址；如果配置了 `udp_extra`，则优先使用该 host。

SIP username 默认更接近真实用户：90% 概率由 `get_email_name()` 生成，组合高频拼音姓名、出生年份、职业、兴趣和分隔符；10% 概率回退到短随机字母数字串。`get_email()` 还可以把用户名与常见真实邮箱域名池组合成完整邮箱地址。

## 自定义二进制负载

二进制 payload 模式会覆盖协议生成器。

TCP：

```sh
printf 'hello\r\n' > /proc/garble/tcp_payload
sysctl -w net.garble.enable_tcp_binary_payload=1
```

UDP：

```sh
printf 'hello' > /proc/garble/udp_payload
sysctl -w net.garble.enable_udp_binary_payload=1
```

大小上限由 `GARBLE_MAX_TCP_PAYLOAD` 和 `GARBLE_MAX_UDP_PAYLOAD` 决定。

## Payload file profile

`payload_file` profile 会从对应 procfs 目录随机选择一个非空托管文件：

```sh
/proc/garble/tcp/payload_file/
/proc/garble/udp/payload_file/
```

通过 `ctl` 创建、查看和删除文件：

```sh
echo 'create p1' > /proc/garble/tcp/payload_file/ctl
printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > /proc/garble/tcp/payload_file/p1
cat /proc/garble/tcp/payload_file/ctl
echo 'delete p1' > /proc/garble/tcp/payload_file/ctl
```

UDP 使用同样流程：

```sh
echo 'create u1' > /proc/garble/udp/payload_file/ctl
printf 'hello' > /proc/garble/udp/payload_file/u1
cat /proc/garble/udp/payload_file/ctl
echo 'delete u1' > /proc/garble/udp/payload_file/ctl
```

`ctl` 文件本身不会进入随机池。只有通过 `ctl` 创建且内容非空的文件才会被选中。

## Domains

`domains` 是逗号分隔的域名列表，供 HTTP、HTTP download、DTLS 生成器作为 Host 或 SNI 使用。

`domains_tls` 是独立的逗号分隔域名列表，供 TCP TLS 负载使用，包括 `tls` / `tls_clienthello` 和 `tlsv1` / `tlsv1_clienthello`。

```sh
sysctl -w net.garble.domains=example.com,www.example.com
sysctl -w net.garble.domains_tls=tls.example.com,www.example.com
```

需要域名的 profile 在未配置对应域名池时可能生成失败，最终不会发送伪造包。TLS profile 使用 `domains_tls`；HTTP 和 DTLS profile 使用 `domains`。

## 统计和诊断

查看计数器：

```sh
cat /proc/garble/stats
```

查看可用 profile ID：

```sh
cat /proc/garble/protos
```

协议配置写入成功后，内核日志会打印选中的协议集合和解析后的权重。

## 常见配置示例

TCP 加权混合：

```sh
sysctl -w net.garble.domains=example.com
sysctl -w net.garble.domains_tls=tls.example.com
sysctl -w net.garble.tcp_obf_proto=tls=350,http=250,sip=200,ssh,mqtt
sysctl -w net.garble.tcp_repeat_pkt=3
```

HTTP 搜索类流量：

```sh
sysctl -w net.garble.tcp_obf_proto=http_search_tieba,http_search_imooc,http_download
```

UDP SIP/DTLS/TURN 混合：

```sh
sysctl -w net.garble.enable_udp=1
sysctl -w net.garble.udp_obf_proto=sip=400,dtls=300,turn=300
```

TCP payload 文件池：

```sh
echo 'create p1' > /proc/garble/tcp/payload_file/ctl
printf 'custom payload' > /proc/garble/tcp/payload_file/p1
sysctl -w net.garble.tcp_obf_proto=payload_file
```

## 注意事项

- `tcp_obf_proto` 和 `udp_obf_proto` 会被解析成 RCU 保护的权重配置，包路径不会直接解析 sysctl 字符串。
- 非法协议配置会被拒绝，并且不会替换当前生效配置。
- 空 `tcp_obf_proto` 或 `udp_obf_proto` 表示关闭对应可配置 profile 集合。
- UDP 必须设置 `enable_udp=1`；TCP 可配置 profile 没有单独的总开关。
