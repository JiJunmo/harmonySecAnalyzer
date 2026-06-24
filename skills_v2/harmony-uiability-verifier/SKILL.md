---
name: harmony-uiability-verifier
description: UIAbility 入口安全专家规则库。专职校验 Calling Bundle 限制、Want 重定向、敏感回传与重入一致性。
---

# harmony-uiability-verifier

本技能是一个纯粹的无状态规则库工具，专门用于对给定的鸿蒙 UIAbility 代码执行入口防卫漏洞扫描。

## 📁 目录结构

* `references/`
  * [ABILITY_REFERENCE.md](file:///Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer/skills_v2/harmony-uiability-verifier/references/ABILITY_REFERENCE.md) — UIAbility 入口防卫与生命周期知识库
* `rules/`
  * `ability/` — 包含 UIAbility 匹配规则集（CWE/OWASP）

---

## 🔍 UIAbility 入口校验指南 (UIAbility Check)

**校验重点**：检查 `exported=true` 的公开 Ability 在生命周期入口中提取并消费 `want` 参数时的防御等级。

**核对要点**：
1. **Calling Bundle 校验**：是否调用了 `getCallingBundleName()` 并设置了严格的白名单比对？
2. **Ability 重定向校验**：嵌套的 `Want` 变量是否最终作为参数流入了 `context.startAbility(nestedWant)`？若存在，是否有目标组件白名单拦截？
3. **敏感信息回传校验**：`terminateSelfWithResult(resultWant)` 返回的数据中是否泄露了敏感的 token、沙箱文件路径或本地数据库信息，且缺乏 Caller 身份安全拦截？
4. **重入漏洞校验**：`onCreate(want)` 和 `onNewWant(want)` 的校验逻辑是否具备**防御一致性**？若 `onNewWant` 缺少校验，攻击者可通过重入机制实现绕过。
