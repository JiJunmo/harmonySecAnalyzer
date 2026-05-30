import emitter from '@ohos.events.emitter';

const EVENT_LOAD_WEB = 10001;

@Entry
@Component
struct MainPage {
  @State message: string = 'Hello World';

  aboutToAppear() {
    // 3. 事件发射 (测试全局总线 Emitter 桥接)
    let eventData = {
      data: {
        targetToken: "tainted_auth_token_from_want"
      }
    };
    emitter.emit({ eventId: EVENT_LOAD_WEB }, eventData);
  }

  build() {
    Row() {
      Column() {
        Text(this.message)
          .fontSize(50)
          .fontWeight(FontWeight.Bold)
      }
      .width('100%')
    }
    .height('100%')
  }
}
