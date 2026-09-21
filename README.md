# NetM

通过一根 Type-C / 雷电线，把**宿主机**已经接入的以太网或 Wi-Fi 共享给**客机**。客机上的应用不需要改代理：虚拟网卡接管默认路由，真实出口在宿主机上。

```text
客机上的应用 → TUN 10.77.0.2 → Type-C 隧道 → 宿主机用户态协议栈 → 以太网 / Wi-Fi
```

当前版本是隧道模式：宿主机全程用户态，不需要管理员权限；客机需要管理员权限（创建 TUN、改路由）。关掉客机终端（`q` / Ctrl-C / 关窗口）或拔掉线，路由和 DNS 都会撤掉，流量回到本机网络。

## 线缆

- **推荐**：雷电 3/4 或 USB4 线，两端都是雷电/USB4 口。插上后系统会出现以太网链路（Mac 上常见 `bridge0` 或热插拔出来的 `enN`），这是主通道。
- **普通 USB-C**（非雷电）：充电线通常**没有**网卡。线或转接如果会冒出 USB Ethernet（Mac 上常见热插拔 `enN`、链路本地 `fe80` / `169.254`），可以走隧道。这类网卡经常丢掉 `ff02::1` 组播，客机会改对 NDP/ARP 邻居单播探测，再不行就直连邻居的 TCP 27778。如果两端已经由 USB CDC/串口驱动提供设备节点，也可以显式选择串口传输；普通 C-to-C 充电线本身不会凭空创建串口。
- Mac mini 上 `en0` 是机身有线网口，不是 Type-C 链路。Type-C 热插拔出来的接口可能暂时不会出现在「系统设置 → 网络」里，NetM 仍然会枚举它。

## 平台

| 系统 | 状态 |
| --- | --- |
| macOS | 本机实测（Apple Silicon） |
| Linux | 已实现（`ip` / `resolvectl`），未在真机验证 |
| Windows | 已实现（Wintun / `netsh` / `route`），未在真机验证；客机需要 `wintun.dll` |

## 构建

```bash
cargo build --release
# 二进制：target/release/netm   （约 5 MB，不要拷整个 target/）
```

首次运行如果被 Gatekeeper 拦截：

```bash
chmod +x netm
xattr -d com.apple.quarantine netm
```

## 用法

```bash
netm              # 首次：Onboarding 选宿主机 / 客机，之后记住默认
netm setup        # 重新选择默认模式
netm host         # 直接当宿主机（不需要 sudo）
netm guest        # 直接当客机（会自动 sudo 提权）
netm host --headless
netm guest --headless --route 1.1.1.1/32 --no-dns
netm host --serial /dev/tty.usbmodem1234 --baud 921600
netm guest --serial /dev/tty.usbmodem5678 --baud 921600
```

按键：`q` 退出（先清理再关），`m` 切换并保存默认模式，`l` 滚动日志，`?` 帮助。

客机连上后会立刻在 Type-C 链路上打一小段包，测的是**这条线的上限**，不是互联网速度。结果写在连接面板的「线路」和日志里。

只想测协议链路而不创建 TUN、修改 DNS 或接管任何系统流量时，可以在客机源码目录运行：

```bash
cargo run -p netm-proto --release --example remote_link_bench -- \
  '[fe80::xxxx%7]:27778'
```

它会输出双向吞吐和 200 次协议 RTT；`%7` 是客机侧接口索引。这个诊断只短暂连接宿主机的 TCP 27778，不需要 `sudo`。

串口传输使用带 `NETM` 魔数的可重新同步帧，即使一端晚启动或串口里残留半帧也会自动找回边界。宿主机可同时监听 TCP 和一个串口，但所有传输合计只允许一台客机占用隧道。

拔线后客机顶部会提示「隧道已撤销，流量已回到本机网络（en0 / Wi-Fi）」。不要在隧道还在的时候拔线不管——程序会在约 0.4 秒内撤路由，但那之前数据包会进黑洞。

### 指定宿主机（跳过发现）

```bash
netm guest --host '[fe80::xxxx%en6]:27778'
```

`%` 后面是**客机**这边的网卡名。

### 单机自测

两端跑在同一台机器上时，只劫持一个地址，否则默认路由会打环：

```bash
# 终端 1
./target/release/netm host --headless

# 终端 2
sudo -E ./target/release/netm guest --headless --route 1.1.1.1/32 --no-dns
```

## 配置与日志

- 配置：`~/.config/netm/config.toml`（sudo 时按 `SUDO_USER` 的家目录，可用 `NETM_CONFIG` 覆盖）
- 日志（TUI）：同一目录下的 `netm.log`
- 虚拟网段：客机 `10.77.0.2/24`，网关/DNS `10.77.0.1`

## 权限

- 宿主机：普通用户
- 客机：macOS/Linux 需要 root；Windows 需要提权。TUI 模式下客机会自动 `sudo` 重新执行自己

## 排错

- 宿主机链路列表里只有 `en0`：那是机身网口。确认线插上后客机/宿主机是否出现新的 `enN` 或 `bridge0` 为「已连线」。热插拔接口不在 `networksetup` 里也没关系。
- 客机停在「发现宿主机中」：两端都要换成带邻居回退的新二进制。普通 Type-C 以太网常丢组播，新版本会打「组播未应答，改为直连邻居」。仍失败时重启宿主机上的 `netm host`（线已经插上再开），或 `netm guest --host '[fe80::xxxx%en6]:27778'`。检查防火墙是否拦了 UDP 27777 / TCP 27778。
- 宿主机服务没开时客机仍会尝试连接：自动发现还可能从系统的 NDP/ARP 邻居表找到上次的地址；为了让宿主机稍后启动时能自动恢复，客机不会彻底停止，而是按 1、2、4、8、16、30 秒退避，之后最多每 30 秒尝试一次。真实会话建立后退避会重置。
- 日志出现 `unknown frame type 7` / `Broken pipe`：两端版本不一致，旧版不认识线路测速帧。请把宿主机和客机都替换为同一份 `netm`；TUI 左上角和 `netm --version` 都会显示版本号。
- `scutil --dns` 里看不到 `10.77.0.1`：域名解析可能仍走原来的 DNS；IP 直连不受影响。
- 拔线后没网：按 `q` 或 Ctrl-C，确认 `netstat -rn` 里 `0/1` 和 `128/1` 已经消失。

## 仓库结构

- `crates/netm-proto`：帧协议、发现、网卡枚举、线路测速
- `crates/netm-host`：用户态协议栈转发
- `crates/netm-guest`：TUN、路由、DNS、状态机
- `crates/netm-cli`：TUI / CLI

## 后续

NAT 模式、应用层代理、USB gadget。
