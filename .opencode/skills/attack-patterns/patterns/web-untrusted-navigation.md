# web-untrusted-navigation

## 根因

外部输入控制 Web 的实际加载目标,突破 scheme、origin、路径或重定向后的页面信任边界。

## 必须证明

- 外部字段到达 `Web.src`/`loadUrl`/navigation callback 的真实 URL 参数。
- 攻击者控制最终 scheme/host/port/path 或危险 scheme。
- 不可信内容获得超过公开浏览能力的具体应用上下文影响。

## 有效反证

- 结构化 URL 解析后的精确 scheme/host/port/path allowlist。
- 危险 scheme 拒绝,并对每次重定向后的最终 URL 重复执行同一策略。

## 正常业务

固定本地页、不可变页面 ID 映射或有界公开网页浏览。

## 禁止推理

- 因存在 Web 组件、外部 deeplink 或 JSBridge 就确认导航漏洞。
- 只分析初始 URL,忽略真正加载的最终目标。

## 证据要求

Manifest 输入 trace、实际 URL sink、最终 origin、导航 guard 的支配关系和页面信任边界影响。
