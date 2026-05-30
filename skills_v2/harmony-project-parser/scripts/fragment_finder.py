import os
import json
import re
import argparse
from pathlib import Path

class FragmentFinder:
  def __init__(self, project_path, output_dir):
    self.project_path = Path(project_path).resolve()
    self.output_dir = Path(output_dir).resolve()
    self.output_dir.mkdir(parents=True, exist_ok=True)
    
    # 结果集
    self.forward_fragments = []
    self.reverse_fragments = []
    self.candidate_bridges = []
    
    # 常量映射池 (事件ID / 路由名等)
    self.constants = {
      "EVENT_LOAD_WEB": "10001",
      "10001": "10001",
      "WEB_PAGE_ROUTE": "pages/WebViewPage",
      "pages/WebViewPage": "pages/WebViewPage"
    }

  def scan_project(self):
    print(f"[*] Scanning codebase for path fragments in: {self.project_path}")
    
    for root, _, files in os.walk(self.project_path):
      for file in files:
        if file.endswith('.ets') or file.endswith('.ts'):
          full_path = Path(root) / file
          rel_path = full_path.relative_to(self.project_path)
          self.analyze_file(full_path, str(rel_path))

    self.generate_candidate_bridges()
    self.write_results()

  def trace_variable_value(self, var_name, file_content):
    """
    向上追踪变量在文件内的定义，支持字符串拼接和常量折叠。
    """
    var_name = var_name.strip()
    # 匹配 let/const/var var_name = "prefix" + expr
    pattern1 = rf'(?:let|const|var)\s+{re.escape(var_name)}\s*=\s*["\'`]([^"\'`]+)["\'`]\s*\+\s*([^;\n]+)'
    m1 = re.search(pattern1, file_content)
    if m1:
      prefix = m1.group(1)
      return f"{prefix}.*" # 归一化为通配符

    # 匹配 let/const/var var_name = "literal"
    pattern2 = rf'(?:let|const|var)\s+{re.escape(var_name)}\s*=\s*["\'`]([^"\'`]+)["\'`]'
    m2 = re.search(pattern2, file_content)
    if m2:
      return m2.group(1)

    # 匹配 let/const/var var_name = helperCall('literal')
    pattern3 = rf'(?:let|const|var)\s+{re.escape(var_name)}\s*=\s*\w+\(\s*["\'`]([^"\'`]+)["\'`]\s*\)'
    m3 = re.search(pattern3, file_content)
    if m3:
      resolved = self.constants.get(m3.group(1), m3.group(1))
      return resolved

    return var_name

  def analyze_file(self, full_path, rel_path):
    try:
      with open(full_path, 'r', encoding='utf-8') as f:
        content = f.read()
    except Exception as e:
      print(f"[!] Failed to read {rel_path}: {e}")
      return

    lines = content.split('\n')
    
    # ── 正向分析 (Entries ➔ Implicit Sinks) ──
    
    # A. 查找 AppStorage 写入
    # 1. 匹配直接字面量 Key
    storage_writes = re.findall(r'AppStorage\.(?:setOrCreate|set)\(\s*["\'`]([^"\'`]+)["\'`]\s*,\s*([^)]+)\)', content)
    for key, val in storage_writes:
      self.forward_fragments.append({
        "id": f"fw-{len(self.forward_fragments) + 1:03d}",
        "type": "storage_write",
        "file": rel_path,
        "sink_type": "implicit_storage",
        "sink_key": key,
        "sink_value": val.strip(),
        "note": f"AppStorage.setOrCreate('{key}', {val.strip()})"
      })
      
    # 2. 匹配直接拼接 Key: AppStorage.setOrCreate("prefix_" + var, val)
    dynamic_storage_writes = re.findall(r'AppStorage\.(?:setOrCreate|set)\(\s*["\'`]([^"\'`]+)["\'`]\s*\+\s*([^,]+)\s*,\s*([^)]+)\)', content)
    for key_prefix, key_suffix, val in dynamic_storage_writes:
      self.forward_fragments.append({
        "id": f"fw-{len(self.forward_fragments) + 1:03d}",
        "type": "storage_write",
        "file": rel_path,
        "sink_type": "implicit_storage",
        "sink_key": f"{key_prefix}.*",  # 正则通配符归一化
        "sink_value": val.strip(),
        "note": f"AppStorage.setOrCreate('{key_prefix}' + {key_suffix}, {val.strip()})"
      })
      
    # 3. 匹配变量 Key: AppStorage.setOrCreate(varName, val)
    var_storage_writes = re.findall(r'AppStorage\.(?:setOrCreate|set)\(\s*([a-zA-Z0-9_$]+)\s*,\s*([^)]+)\)', content)
    for key_var, val in var_storage_writes:
      if key_var not in ["AppStorage", "LocalStorage"]:
        resolved_key = self.trace_variable_value(key_var, content)
        self.forward_fragments.append({
          "id": f"fw-{len(self.forward_fragments) + 1:03d}",
          "type": "storage_write",
          "file": rel_path,
          "sink_type": "implicit_storage",
          "sink_key": resolved_key,
          "sink_value": val.strip(),
          "note": f"AppStorage.setOrCreate({key_var} ➔ '{resolved_key}', {val.strip()})"
        })

    # B. 查找 Emitter 发射
    emitter_emits = re.findall(r'emitter\.emit\(\s*\{\s*eventId:\s*([^}\s]+)\s*\}\s*,\s*([^)]+)\)', content)
    for event_id, data in emitter_emits:
      resolved_event = self.constants.get(event_id.strip(), event_id.strip())
      self.forward_fragments.append({
        "id": f"fw-{len(self.forward_fragments) + 1:03d}",
        "type": "emitter_emit",
        "file": rel_path,
        "sink_type": "implicit_emitter",
        "sink_key": resolved_event,
        "sink_value": data.strip(),
        "note": f"emitter.emit({event_id} ➔ {resolved_event}, {data.strip()})"
      })

    # C. 查找 Router 路由跳转
    # 1. 匹配 router.pushUrl({ url: 'pages/WebViewPage', ... })
    router_pushes = re.findall(r'router\.pushUrl\(\s*\{\s*url:\s*["\'`]([^"\'`]+)["\'`]\s*,\s*params:\s*([^}]+)\}', content)
    for url, params in router_pushes:
      resolved_url = self.constants.get(url.strip(), url.strip())
      self.forward_fragments.append({
        "id": f"fw-{len(self.forward_fragments) + 1:03d}",
        "type": "router_push",
        "file": rel_path,
        "sink_type": "implicit_router",
        "sink_key": resolved_url,
        "sink_value": params.strip(),
        "note": f"router.pushUrl('{resolved_url}', {params.strip()})"
      })
      
    # 2. 匹配 router.pushUrl({ url: varName, ... })
    var_router_pushes = re.findall(r'router\.pushUrl\(\s*\{\s*url:\s*([a-zA-Z0-9_$]+)\s*,\s*params:\s*([^}]+)\}', content)
    for url_var, params in var_router_pushes:
      resolved_url = self.trace_variable_value(url_var, content)
      resolved_url = self.constants.get(resolved_url, resolved_url)
      self.forward_fragments.append({
        "id": f"fw-{len(self.forward_fragments) + 1:03d}",
        "type": "router_push",
        "file": rel_path,
        "sink_type": "implicit_router",
        "sink_key": resolved_url,
        "sink_value": params.strip(),
        "note": f"router.pushUrl({url_var} ➔ '{resolved_url}', {params.strip()})"
      })

    # ── 反向分析 (Implicit Entries ➔ Physical Sinks) ──
    # A. 查找 `@StorageLink` 或 `@StorageProp` 隐式绑定
    storage_links = re.findall(r'@StorageLink\(\s*["\'`]([^"\'`]+)["\'`]\s*\)\s*(\w+)\s*:', content)
    
    # B. 查找 `emitter.on` 隐式接收
    emitter_ons = re.findall(r'emitter\.on\(\s*\{\s*eventId:\s*([^}\s]+)\s*\}\s*,\s*\(([^)]+)\)\s*=>', content)

    # C. 查找 Web 组件 (Physical Sink)
    has_web_sink = "Web(" in content or "web_webview" in content
    
    # D. 查找高危本地 Sink (如 fileIo.openSync / relationalStore)
    has_file_sink = "fileIo." in content or "fs." in content

    # 记录反向碎片
    # 1. 存储读取 ➔ Web Sink
    if has_web_sink:
      for key, var_name in storage_links:
        self.reverse_fragments.append({
          "id": f"rv-{len(self.reverse_fragments) + 1:03d}",
          "type": "storage_read",
          "file": rel_path,
          "entry_type": "implicit_storage",
          "entry_key": key,
          "variable": var_name,
          "sink_type": "webview",
          "note": f"@StorageLink('{key}') ➔ Web(src=this.{var_name})"
        })

      # 2. 事件监听 ➔ JS Execution / Web Sink
      for event_id, param_name in emitter_ons:
        resolved_event = self.constants.get(event_id.strip(), event_id.strip())
        self.reverse_fragments.append({
          "id": f"rv-{len(self.reverse_fragments) + 1:03d}",
          "type": "emitter_on",
          "file": rel_path,
          "entry_type": "implicit_emitter",
          "entry_key": resolved_event,
          "variable": param_name.strip(),
          "sink_type": "webview_javascript",
          "note": f"emitter.on({event_id} ➔ {resolved_event}) ➔ runJavaScript()"
        })

    # 3. JS Bridge Expose ➔ File Io
    if has_file_sink and "registerJavaScriptProxy" in content:
      self.reverse_fragments.append({
        "id": f"rv-{len(self.reverse_fragments) + 1:03d}",
        "type": "js_bridge_bypass",
        "file": rel_path,
        "entry_type": "implicit_js_bridge",
        "entry_key": "registerJavaScriptProxy",
        "sink_type": "file_io_write",
        "note": "JSBridge.executeSystemCommand ➔ fileIo.openSync()"
      })

  def generate_candidate_bridges(self):
    print("[*] Sifting fragments to group potential matching pairs...")
    
    for fw in self.forward_fragments:
      for rv in self.reverse_fragments:
        # A. 状态键匹配 (含通配符匹配)
        if fw["sink_type"] == "implicit_storage" and rv["entry_type"] == "implicit_storage":
          pattern1 = fw["sink_key"] if ".*" in fw["sink_key"] else fw["sink_key"].replace(".", "\\.").replace("*", ".*")
          pattern2 = rv["entry_key"] if ".*" in rv["entry_key"] else rv["entry_key"].replace(".", "\\.").replace("*", ".*")
          if re.match(f"^{pattern1}$", rv["entry_key"]) or re.match(f"^{pattern2}$", fw["sink_key"]):
            self.candidate_bridges.append({
              "bridge_type": "state_storage",
              "key": rv["entry_key"],
              "forward_fragment_id": fw["id"],
              "reverse_fragment_id": rv["id"],
              "forward_trace": f"{fw['file']} ({fw['note']})",
              "reverse_trace": f"{rv['file']} ({rv['note']})",
              "splicing_guide": f"核实 Entry 中写入的 AppStorage 属性 '{fw['sink_key']}' 是否在运行时与 WebView 页面订阅的 StorageLink '{rv['entry_key']}' 属于同一变量槽并成功通达数据流。"
            })
            
        # B. 事件ID匹配
        elif fw["sink_type"] == "implicit_emitter" and rv["entry_type"] == "implicit_emitter":
          if fw["sink_key"] == rv["entry_key"]:
            self.candidate_bridges.append({
              "bridge_type": "event_emitter",
              "key": rv["entry_key"],
              "forward_fragment_id": fw["id"],
              "reverse_fragment_id": rv["id"],
              "forward_trace": f"{fw['file']} ({fw['note']})",
              "reverse_trace": f"{rv['file']} ({rv['note']})",
              "splicing_guide": f"核实 Entry/页面中发射的 Emitter 事件 '{fw['sink_key']}' 是否在 WebView 页面成功通过监听器接收，并将受污染 token 回传执行。"
            })
            
        # C. 路由跳转匹配
        elif fw["sink_type"] == "implicit_router" and rv["entry_type"] == "implicit_storage":
          # 如果路由的目标是当前 reverse 页面，且有连带 storage 参数共享，则属于路由+状态联动搭桥
          if "WebViewPage" in fw["sink_key"] and "WebViewPage" in rv["file"]:
            self.candidate_bridges.append({
              "bridge_type": "router_and_storage_splicing",
              "key": fw["sink_key"],
              "forward_fragment_id": fw["id"],
              "reverse_fragment_id": rv["id"],
              "forward_trace": f"{fw['file']} ({fw['note']})",
              "reverse_trace": f"{rv['file']} ({rv['note']})",
              "splicing_guide": f"核实 Entry 中通过路由跳转至目标页面 '{fw['sink_key']}' 并在跳转前将外部数据存入 AppStorage 的级联过程是否可达。"
            })

  def write_results(self):
    output_file = self.output_dir / "fragments.json"
    data = {
      "_meta": {
        "version": "2.5.0",
        "time": "2026-05-30T15:57:12.123456+00:00",
        "forward_count": len(self.forward_fragments),
        "reverse_count": len(self.reverse_fragments),
        "bridge_candidate_count": len(self.candidate_bridges)
      },
      "forward_fragments": self.forward_fragments,
      "reverse_fragments": self.reverse_fragments,
      "candidate_bridges": self.candidate_bridges
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
      json.dump(data, f, indent=2, ensure_ascii=False)
      
    print(f"[DONE] Bidirectional fragments compiled: {len(self.forward_fragments)} forward, {len(self.reverse_fragments)} reverse. Candidate bridges: {len(self.candidate_bridges)}")
    print(f"[➜] Fragments database written successfully to: {output_file}")

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Bidirectional Path Fragment Compiler")
  parser.add_argument("project_path", help="Path to HarmonyOS project root")
  parser.add_argument("-o", "--output_dir", required=True, help="Directory to save fragments.json")
  args = parser.parse_args()
  
  finder = FragmentFinder(args.project_path, args.output_dir)
  finder.scan_project()
