import web_webview from '@ohos.web.webview';
import emitter from '@ohos.events.emitter';
import fileIo from '@ohos.file.fs';

const EVENT_LOAD_WEB = 10001;

class JSApiBridge {
  constructor() {}

  // 4. 高危 JS Bridge 方法
  public executeSystemCommand(cmd: string, path: string): void {
    if (cmd === "writeFile") {
      let file = fileIo.openSync(path, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
      fileIo.writeSync(file.fd, "Malicious write from webview bridge");
      fileIo.closeSync(file);
    }
  }
}

@Entry
@Component
struct WebViewPage {
  controller: web_webview.WebviewController = new web_webview.WebviewController();
  
  // 5. 状态变量接收 (测试 StorageLink 隐式连通)
  @StorageLink('global_web_url_phone') currentWebUrl: string = "https://default.com";
  @State activeToken: string = "";

  aboutToAppear() {
    // 6. 事件监听接收 (测试 Emitter 连通)
    emitter.on({ eventId: EVENT_LOAD_WEB }, (eventData) => {
      let token = eventData.data?.targetToken as string;
      if (token) {
        this.activeToken = token;
        this.controller.runJavaScript("onTokenLoaded('" + token + "')");
      }
    });
  }

  build() {
    Column() {
      // WebView 终点 (Sink)
      Web({ src: this.currentWebUrl, controller: this.controller })
        .width('100%')
        .height('100%')
        .onConfirm((event) => {
          return false;
        })
        .onLoadIntercept((event) => {
          // onLoadIntercept 弱安全域名校验
          let url = event.data.getRequestUrl();
          if (url.includes("trusted.com")) {
            return false;
          }
          return true;
        })
        .aboutToAppear(() => {
          // 注册高危 JS Bridge
          this.controller.registerJavaScriptProxy(
            new JSApiBridge(),
            "JSApi",
            ["executeSystemCommand"],
            [],
            [] // 缺失 allowedOriginRules 限制
          );
        })
    }
  }
}
