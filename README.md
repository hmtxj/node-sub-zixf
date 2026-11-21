# 免费节点订阅 · 每 6 小时自动更新（V2rayN / Clash / Mihomo）

> 全自动的**免费 v2ray / clash 节点订阅**：每 6 小时聚合 9 个公开源，自动**清洗广告节点、去重、TCP 存活检测**，
> 再做**家宽 ASN 筛查**，输出可直接导入 **V2rayN / v2rayNG / Clash / Mihomo / sing-box** 的订阅链接。
> Free v2ray & clash nodes subscription, auto-updated every 6 hours by GitHub Actions.
> Fork 自 [chenzhihan1751-cyber/node-sub-zixf](https://github.com/chenzhihan1751-cyber/node-sub-zixf)，新增 Clash 直出 + 家宽筛查。

## 订阅地址（复制即用）

**Clash / Mihomo（直接导入完整配置，美国住宅优先）**

```
https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/clash.yaml
```

**V2rayN / v2rayNG / Shadowrocket（base64 订阅）**

```
https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/base64.txt
```

**明文节点列表**（想手动挑几条时看这个）

```
https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/v2ray.txt
```

**家宽（实测为住宅 ISP 的节点，美国优先）**

```
https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/jia-kuan.txt
```

**美国真住宅**

```
https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/us-residential.txt
```

**美国全部节点**

```
https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/us-only.txt
```

**国内直连 raw 不稳时的镜像**（路径不变，只换域名）

```
https://hk.gh-proxy.com/https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/base64.txt
```

```
https://gh-proxy.com/https://raw.githubusercontent.com/hmtxj/node-sub-zixf/main/sub/base64.txt
```

## 怎么用

**Clash / Mihomo**：把上面 `sub/clash.yaml` 的 raw 链接当配置文件导入（Clash Verge / Stash → 配置文件 → 从 URL 导入），
里面已经按“美国住宅 → 其他家宽 → 其余节点”排好序，还有 `🇺🇸 美国住宅` / `🏠 家宽` 两个分组，点一下同步就是最新版。

**V2rayN / v2rayNG**：`订阅 → 订阅分组 → 添加订阅` 填上面的 base64 链接 → `更新订阅（含节点）` →
`设置 → 参数设置 → 订阅` 勾「自动更新订阅」，间隔填 `360` 分钟，之后就不用管了。

## 家宽筛查是怎么做的

- 每个存活节点先 DNS 解析出 IP，再用 ipinfo.io（无 key）查国家 / ASN / org，失败时用 ip-api.com 免费接口兜底。
- org 是 Comcast、Charter/Spectrum、Cox、AT&T、Verizon、Frontier、Free、Orange、Fastweb、Korea Telecom、SK Broadband、
  China Mobile、T-Mobile、Hargray 等家庭宽带运营商的，算真家宽；ASN 是住宅 ISP 但使用者是机房公司的，单列为“静态 ISP”，不算真家宽。
- 没有单一官方“人类指数”，这里不编分数，查不到的标 unknown。结果写在 `sub/stats.json` 里（`jiaKuan` / `usResidential` / `usTotal` / `staticIsp` / `datacenter` / `ipUnknown`）。
- 查过的 IP 会缓存到 `sub/ip-cache.json`，下次只查新 IP，省额度、跑得快。
- **家宽会累积，不会丢**：历轮筛到的家宽都存在 `sub/jia-kuan-archive.json` 里（按 `协议|host|port` 去重），
  每轮先把存档里的家宽重新 TCP 复核一遍，活着的复活进订阅，死了的只标 `dead`、不进订阅、但永远留在存档里
  （不自动删除，只能手动删）。所以 `sub/jia-kuan.txt` 是累积后的活家宽，不是某一轮的 2–8 条。
  全部输出（base64 / v2ray / clash）里家宽永远排最前面，不分国家。

## 它比"随手找个免费订阅"好在哪

| 处理 | 说明 |
|---|---|
| **清洗** | 丢掉 remark 里带「剩余流量 / 到期 / 机场 / 加群 / 订阅」等字样的引流假节点，以及指向内网段、`127.0.0.1` 的无效地址 |
| **去重** | 按 `协议 + 服务器 + 端口 + 凭据` 计算指纹；同一个 `host:port` 最多保留 2 条，防止某个源刷屏 |
| **存活检测** | 每个节点做一次 TCP 连接测试（3 秒超时、192 并发），只保留连得上的 —— 这一步行情通常能砍掉 **60%～70%** 的死节点 |
| **家宽筛查** | 对存活节点做 ASN 检查，真家宽单独输出 `sub/jia-kuan.txt`，美国真住宅单独输出 `sub/us-residential.txt`，美国优先 |
| **Clash 直出** | 不用 subconverter 转换，`sub/clash.yaml` 就是完整 Clash 配置，vless 的 reality/tls、ws/grpc/xhttp、flow、fp、pbk、sid 都保留 |
| **安全阀** | 检测后节点数异常少时自动退回未检测结果；最终少于 20 个则整个任务失败、不提交，订阅永远停在上一版可用状态 |

原项目实测一轮：**11439 条原始 → 清洗去重 4886 条 → 存活检测后 2000+ 条**，全程约 45 秒。

## 自动化

由 GitHub Actions 驱动（`.github/workflows/update.yml`），每 6 小时跑一次，也在 `sources.txt` / `fetch-nodes.mjs` 变更时触发：

```
sources.txt ──抓取──▶ 解码(base64/明文) ──▶ 清洗 ──▶ 去重 ──▶ TCP 存活检测 ──▶ 家宽 ASN 筛查 ──▶ sub/*
```

| 文件 | 内容 |
|---|---|
| `sub/clash.yaml` | **Clash / Mihomo 完整配置（直接导入）** |
| `sub/base64.txt` | **base64 订阅（v2rayN 客户端填这个）** |
| `sub/v2ray.txt` | 明文节点列表 |
| `sub/jia-kuan.txt` | 真家宽节点链接（**累积**的活家宽，排最前面） |
| `sub/jia-kuan-archive.json` | 家宽累积存档（历轮家宽，含已死的，永不自动删除） |
| `sub/us-residential.txt` | 美国真住宅节点链接 |
| `sub/us-only.txt` | 美国全部节点链接 |
| `sub/stats.json` | 本次抓取统计：每个源成功几条、剔除多少死节点、家宽计数 |
| `sub/ip-cache.json` | ASN 检查缓存 |
| `sources.txt` | 上游源列表，一行一个 |
| `fetch-nodes.mjs` | 聚合脚本，零第三方依赖（Node 18+） |

## 常见问题

**节点质量怎么样？** 免费节点普遍寿命短、限速、时好时坏 —— 这是所有免费源的共同问题，不只是本项目。
订阅里节点很多，**建议导入后自己在客户端里跑一遍「测试真连接延迟」再挑**（TCP 通不代表真能代理）。

**为什么有的节点连不上？** 免费节点由陌生人运营，随时可能下线或被封；TCP 检测只能证明"端口开着"，
代理是否真能用需要客户端实测。

**更新频率**：每 6 小时一次。别人拉取时走的是 GitHub 的 CDN，本项目没有服务器，也不消耗维护者带宽。

## 免责声明

本项目仅自动聚合互联网上**已公开**的节点信息，不生产、不销售、不运营任何节点，也不对可用性作任何保证。
所有节点均来自第三方公开源，使用者需自行判断合规性并承担风险。**请勿在公共免费节点上登录网银、主邮箱等重要账号。**

## License

MIT
