# 鸿蒙 UIAbility 安全域知识参考 (ABILITY_REFERENCE)

在 HarmonyOS 中，`UIAbility` 是应用生命周期的核心载体，也是应用对外暴露交互的最主要物理边界。若在开发中对其导出状态（`exported`）和启动参数（`Want`）处理不当，会产生极高风险的系统级越权漏洞。

---

## 1. UIAbility 生命周期与外部入口 (want)

UIAbility 的启动和重新激活会触发以下两个核心生命周期钩子。外部输入的恶意 `Want` 数据正是通过这两个钩子注入受害 App 的：

### A. onCreate(want: Want, launchParam: AbilityConstant.LaunchParam)
当 Ability **首次创建**时触发。通过 `want` 变量可以提取外部唤醒应用时传入的全部资产：
```typescript
export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    // 首次启动入口：获取 want 并在其中解析 parameters
    let externalData = want.parameters?.sensitive_data;
  }
}
```

### B. onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam)
当 Ability **处于后台且启动模式为 singleton**、重新被外部唤起时触发。它也是捕获外部输入的关键重入点：
```typescript
export default class EntryAbility extends UIAbility {
  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    // 重新被拉起时的重入入口
    let externalData = want.parameters?.sensitive_data;
  }
}
```

---

## 2. 能力重定向漏洞（Ability Redirection）

### 漏洞成因
UIAbility Redirection（在 Android 中常称为 Intent Redirection）是组件暴露中最具破坏力的逻辑漏洞。
当一个 `exported: true` 的 Ability 接收一个外部 `Want` 作为参数（例如 `want.parameters.redirWant`），并没有校验调用方包名或 nested Want 的合法性，直接使用 Native context 将其拉起：
```typescript
// 受害应用代码 (Vulnerable code)
let target = want.parameters?.redirWant as Want;
if (target) {
  this.context.startAbility(target); // 越权代理拉起！
}
```

### 攻击场景与危害
1. **越权调起应用内私有组件**：
   - 攻击者可以构造嵌套 Want，指向受害应用内部未导出（`exported: false`）的 Ability（如 `AdminPageAbility`）。
   - 由于是受害应用自己执行了 `startAbility`，系统会认为这是应用内部的自发调用，从而**直接放行**，导致私有组件完全失守。
2. **越权使用高权限系统服务**：
   - 攻击者可以传入高权限的系统 Ability（如请求系统安装、修改敏感网络配置、调起付款）。
   - 系统在校验权限时，校验的是受害 App 的 UID，而非攻击者 App 的 UID。如果受害 App 拥有此权限，则该高特权操作将被强行代理执行，造成特权提升。

### 攻击 PoC Want Payload 构造示例
```typescript
// 攻击者构造的嵌套 Want Payload
let want: Want = {
  bundleName: "com.victim.app", // 受害应用
  abilityName: "ExportedAbility", // 公开的跳板 Ability
  parameters: {
    // 嵌套的恶意 Want，指向受害应用的私有敏感组件
    redirWant: {
      bundleName: "com.victim.app",
      abilityName: "PrivateAdminAbility",
      parameters: {
        enableSuperAdmin: true,
        dbPath: "/data/storage/el2/base/files/victim.db"
      }
    } as Want
  }
};
context.startAbility(want); // 唤起跳板
```

---

## 3. 敏感数据回传泄露（Result Leakage）

### 漏洞成因
当应用使用 `startAbilityForResult` 启动另一个公开 Ability 时，期望在完成某些授权、支付或选择操作后返回一部分数据。
被唤醒的公开 Ability 在处理完业务后，调用 `terminateSelfWithResult` 将信息打包返回：
```typescript
// 被唤醒的 UIAbility
let resultWant: Want = {
  parameters: {
    userToken: "eyJhbGciOiJIUzI1NiIs...",
    secretFile: "/data/storage/el2/base/files/user_keys.json"
  }
};
this.context.terminateSelfWithResult({
  resultCode: 1,
  want: resultWant
});
```

如果该公开 Ability **没有利用 `getCallingBundleName()` 核实调用者究竟是谁**，就直接无条件塞入敏感数据回传，那么任意安装在手机上的三方应用都可以通过 `startAbilityForResult` 拉起它并读取返回的 result，造成严重的数据泄露。

---

## 4. 纵深防御指南 (Defense & Remediation)

### A. 最小化组件暴露
* 在 `module.json5` 中，凡是没有外部唤醒必要的 UIAbility 或是 ExtensionAbility，**必须强行配置 `"exported": false`**。

### B. 严格调用方包名白名单校验 (仅在 ForResult 时有效)
在回传敏感结果时，必须首先通过 Native 上下文获取 Caller 包名：
```typescript
let callerBundle = this.context.getCallingBundleName();
const TRUSTED_WHITE_LIST = ["com.trusted.partner1", "com.trusted.partner2"];

if (!TRUSTED_WHITE_LIST.includes(callerBundle)) {
  // 拦截，拒绝返回敏感信息
  this.context.terminateSelf();
  return;
}
```

### C. 嵌套 Want 白名单强过滤
如果业务上必须支持 Want 转发（例如分享到微信、调用系统图库），必须将嵌套的 `nestedWant` 反序列化后，对其 `bundleName`、`abilityName` 和 `action` 进行**极其严格的白名单白盒校验**，坚决禁止任意路由转发：
```typescript
let redir = want.parameters?.redirWant as Want;
if (redir) {
  // 仅允许拉起系统浏览器或特定公开组件
  if (redir.bundleName === "com.huawei.hmos.browser") {
    this.context.startAbility(redir);
  } else {
    // 拦截不安全重定向
    hilog.error(0x00, "SEC", "Blocked unsafe redirection target: " + redir.bundleName);
  }
}
```
