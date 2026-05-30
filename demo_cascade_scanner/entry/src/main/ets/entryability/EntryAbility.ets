import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import router from '@ohos.router';

const WEB_PAGE_ROUTE = 'pages/WebViewPage';

function getTargetRoute(alias: string): string {
  if (alias === 'webview') {
    return WEB_PAGE_ROUTE;
  }
  return 'pages/MainPage';
}

export default class EntryAbility extends UIAbility {
  public deviceSuffix: string = "phone";

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    let externalUrl = want.parameters?.externalUrl as string;
    let authToken = want.parameters?.authToken as string;

    if (externalUrl) {
      // 1. 动态 Key 写入 AppStorage (通配符匹配测试)
      let storageKey = "global_web_url_" + this.deviceSuffix;
      AppStorage.setOrCreate(storageKey, externalUrl);
    }

    if (authToken) {
      // 2. 动态路由 + 常量折叠跳转 (路由桥接测试)
      let routePath = getTargetRoute('webview');
      router.pushUrl({
        url: routePath,
        params: { token: authToken }
      });
    }
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    let externalUrl = want.parameters?.externalUrl as string;
    let authToken = want.parameters?.authToken as string;

    if (externalUrl) {
      let storageKey = "global_web_url_" + this.deviceSuffix;
      AppStorage.setOrCreate(storageKey, externalUrl);
    }

    if (authToken) {
      let routePath = getTargetRoute('webview');
      router.pushUrl({
        url: routePath,
        params: { token: authToken }
      });
    }
  }
}
