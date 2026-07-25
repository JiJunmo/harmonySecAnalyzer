# web-untrusted-navigation

## 根因

外部输入控制 Web 实际加载目标,突破 origin/domain/local-resource/navigation-policy 边界,并使页面获得超出公开浏览能力的应用上下文。

## 必须证明

- 外部字段到达 `Web.src`、`WebviewController.loadUrl`、导航 callback 或项目 wrapper 的真实 URL 参数。
- 区分 `full_url|url_components|bounded_selector|fixed`,说明规范化后受控的 scheme/host/port/path/query/fragment/redirect target。
- 区分 initial/programmatic/redirect/new-window/callback 导航,解析最终目标并证明攻击者控制在 decode/normalize/map/rewrite 后仍保留。
- 证明最终页面获得应用认证会话、特权 header、可信 origin 身份、本地资源或持久化应用数据等具体上下文影响。

## 有效反证

- 结构化解析后精确校验 scheme、host、effective port 和必要 path;host 后缀策略具有标签边界。
- 在安全判断前完成 decode/normalize,拒绝策略外 `javascript:`、`file:`、`data:`、`resource:` 等 scheme。
- 同一策略支配真实 sink 及重定向、新窗口和后续程序化导航;明确阻断这些导航也可闭合。
- 外部值只选择不可变 URL 映射,或实际加载目标与外部值无关。

## 正常业务

固定本地帮助页、有界 article/topic 映射、完整最终目标策略约束的合作方页面,以及不携带应用身份/特权数据/本地资源/Native 能力的隔离公开浏览器。

## 禁止推理

- 因存在 Web、deeplink、HTTP URL 或 JSBridge 就确认漏洞;JSBridge 由独立 Pattern 判断。
- 把任意公开网页浏览、URL 字符串参与拼接或页面加载成功自动视为 URL 控制、越界或具体影响。
- 只分析初始 URL,或把 substring/无边界 suffix/解码前字符串校验自动视为有效 allowlist。

## 证据要求
Operation Group 必须记录导航操作、控制模式、受控组件、导航阶段、最终目标状态和上下文证据；组件分析必须复核 Guard 覆盖、最终目标、上下文能力和边界结果。依赖隐藏这些事实时记录 gap/insufficient evidence。
