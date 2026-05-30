import ExtensionAbility from '@ohos.app.ability.ExtensionAbility';
import Want from '@ohos.app.ability.Want';
import rpc from '@ohos.rpc';

class IPCStub extends rpc.RemoteObject {
  constructor(des: string) {
    super(des);
  }

  onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence, option: rpc.MessageOption): boolean {
    // 缺乏 getCallingUid() 校验
    if (code === 1) {
      let cmd = data.readString();
      // 执行系统操作
      return true;
    }
    return false;
  }
}

export default class SecureIPCExt extends ExtensionAbility {
  onConnect(want: Want): rpc.RemoteObject {
    return new IPCStub("SecureIPCExtStub");
  }
}
