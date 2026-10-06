# gvl-recon · 前端静态源码业务链路解析工具

> **本工具仅采集网站公开静态 HTML、JS、配置文件，不会探测、发包、扫描任何接口；使用者必须持有目标站点书面授权。**
> 所有接口连通性测试、漏洞验证、业务伤害判定均由**人工**完成。所有风险结论均为**【静态源码推断，未实测】**。

纯静态情报分析工具，零主动探测发包：自动化读取网站公开的 HTML/JS/配置文件，做 AST 解析 + LLM 语义理解，从源码推导业务交互链路。

---

## 一、边界铁律（不可修改）

| 工具做什么 | 工具不做什么 |
| --- | --- |
| 下载站点**公开静态资源**（HTML/JS/CSS/配置） | ✗ 不向提取出来的 API 发送任何请求 |
| AST 解析 + 正则兜底提取接口 | ✗ 不扫描端口 |
| LLM 语义理解（业务功能/分层/依赖） | ✗ 不 Fuzz、不爆破 |
| 组装业务链路、生成 Markdown 报告 | ✗ 不做漏洞验证 |

**角色分工**：Agent 只做枯燥的源码读取、提取、链路梳理；人工负责全部接口连通性测试、漏洞验证、业务伤害判定。

## 二、技术选型

- 语言：Python 3.10+
- HTTP：httpx（仅下载公开静态资源本身）
- HTML 解析：BeautifulSoup4
- AST 解析：`tree-sitter`（首选，错误容忍，能解析现代/压缩 JS）→ `acorn-python`（优先探测）→ `esprima`（稳定兜底，纯 Python）→ 正则兜底
- 可选增强：jsluice（Go 二进制，放入 `bin/` 自动按平台加载，用户无感）
- LLM（可选，默认关闭）：`auto`（配 Key 自动启用）/ OpenAI 兼容 API / Ollama 本地模型 / mock / off，接口抽象可插拔
- 输出：Markdown + JSON
- 网页版：FastAPI + SQLite（授权记录 + 任务状态 + 限流计数）+ 单文件 HTML 前端
- 打包：PyInstaller 一键 exe；容器：Docker

## 三、快速开始

### 形态B：命令行（核心引擎）

```bash
pip install -r requirements.txt

# 默认即可运行，无需任何 LLM 配置（LLM 为可选功能，默认关闭）
python main.py --target http://vul001.test --output ./output/

# 可选：启用 LLM 语义分析（默认 auto：检测到 LLM_API_KEY 即自动启用 OpenAI 兼容服务）
export LLM_API_KEY=sk-xxx
export LLM_BASE_URL=https://api.deepseek.com/v1   # 任意 OpenAI 协议端点：DeepSeek/通义/智谱/Kimi 等
export LLM_MODEL=deepseek-chat
python main.py --target http://vul001.test --output ./output/

# 可选：使用本地 Ollama（需先在本机 ollama serve，离线可用）
LLM_PROVIDER=ollama OLLAMA_MODEL=qwen2.5:7b \
  python main.py --target http://vul001.test --output ./output/

# 内置 mock 启发式（离线演示/测试，不发网络请求，非真实 LLM）
python main.py --target http://vul001.test --llm-provider mock --confirm

# 本地目录模式（零网络请求）：直接读取 target 目录下全部静态文件
# 适用于离线审计打包的前端源码 / CI 环境 / 无外网靶场
python main.py --target ./gvl_static --local --output ./output/
```

交互式运行会弹出**授权确认弹窗**；`--confirm` 用于已取得书面授权的自动化场景。
`--local` 本地目录模式下，target 为本地路径（如 `./gvl_static`），工具直接读取目录内
HTML/JS/配置递归解析，不发起任何 HTTP 请求；被引用但缺失的 chunk 会记录在报告的
"未解析的 chunk" 区块并容忍继续（不编造缺失内容）。

### 形态A：网页版（主打，用户零安装）

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
# 浏览器打开 http://127.0.0.1:8000
# 输入域名 → 勾选授权承诺 → 开始分析 → 轮询进度 → 在线预览 + 下载 Markdown
```

- 长任务后台异步执行，前端轮询进度；
- 后端统一配置 LLM API Key（环境变量）；
- 每 IP 每日免费次数限制：`MAX_TASKS_PER_IP_DAY`（默认 5，付费扩容调大即可）；
- 可选访问令牌：`WEB_TOKEN=xxx` 后前端请求需带 `X-Auth-Token` 头。

### 形态C：Docker（开发者）

```bash
docker build -t gvl-recon .
docker run -p 8000:8000 gvl-recon                        # 网页版
docker run gvl-recon python main.py --target http://vul001.test --output /app/output
```

## 四、端到端工作流（5 阶段）

| 阶段 | 模块 | 说明 |
| --- | --- | --- |
| 1 前置准入校验 | `auth_check.py` | 授权确认弹窗；任务ID/目标/时间/IP/确认状态落库 SQLite；未确认终止 |
| 2 静态资源采集 | `collector.py` | 请求首页 → 提取静态资源 → 递归发现动态 chunk（`import()`）；三道保护：单文件 2MB / 递归 10 层 / 总数 500；默认仅同域 |
| 3a AST 解析 | `ast_parser.py` | tree-sitter→acorn→esprima→正则四保险；axios/fetch/$.ajax/XHR/封装函数/import 别名调用；过滤噪音；自动去重；记录文件:行号 |
| 3b LLM 语义分析 | `llm_analyzer.py` | JSON 固定 schema；防幻觉（清单外接口一律丢弃）；解析失败降级正则；置信度标低 |
| 4 业务链路组装 | `chain_builder.py` | 按固定模板组装链路；标注前置依赖/后续调用；风险族映射仅作静态推断提示 |
| 5 报告生成 | `report_generator.py` | Markdown（概览+链路详情+统计）+ interfaces.json + chains.json |

## 五、输出目录

```
output/
├── raw_js/          # 原始 JS 备份（按 URL hash 命名）
├── interfaces.json  # 接口清单（url/method/params/来源:行号/置信度）
├── chains.json      # 业务链路
└── report.md        # 最终报告（所有风险标注【静态源码推断，未实测】）
```

**置信度规则**：高（AST 直接命中）/ 中（LLM 推断）/ 低（正则兜底）。

## 六、LLM Provider 配置（可选，默认关闭）

LLM 语义分析是**可选增强，不是核心功能**。采集 / AST 提取 / 去重 / 硬编码密钥识别在完全不配置
LLM 时即可完整运行；未启用时漏洞类型映射走内置关键词规则（准确率有限，报告中会明确提示
"建议配置 LLM 后重跑"）。系统**不会**因为没配 LLM 而发起任何请求或报错。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LLM_PROVIDER` | `auto` | `auto` / `openai` / `ollama` / `mock` / `off` |
| `LLM_API_KEY` | 空 | OpenAI 兼容服务的 Key（`auto` 模式下配了它即自动启用） |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | 兼容 OpenAI 协议的任意服务（DeepSeek/通义/智谱/Kimi 等） |
| `LLM_MODEL` | `gpt-4o-mini` | 模型名 |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama 服务地址 |
| `OLLAMA_MODEL` | `qwen2.5:7b` | Ollama 模型名 |

**可插拔判定逻辑（`auto` 为默认值）：**

- `auto` + 已配置 `LLM_API_KEY` → 自动走 OpenAI 兼容协议启用 LLM；
- `auto` + 未配置 `LLM_API_KEY` → 自动关闭（默认零 LLM 请求，走关键词规则）；
- `openai` 但未配置 Key → 安全降级为关闭，**绝不带空 Key 发包**；
- `ollama` → 连接本机 Ollama（不依赖 API Key，需自行 `ollama serve`）；
- `mock` → 内置启发式（离线演示，非真实 LLM）；`off` → 显式强制关闭。

网页版（形态A）由服务器端通过上述环境变量统一配置 Key，使用者无需填写。

## 七、一键 EXE 打包

```bash
pip install pyinstaller
python build_exe.py          # 产物在 dist/gvl-recon(.exe)
./dist/gvl-recon --target http://vul001.test --output ./output/
```

## 八、项目结构

```
gvl-recon/
├── main.py                      # 命令行入口（形态B）
├── app.py                       # FastAPI 网页版后端（形态A）
├── config.py                    # 配置（环境变量全覆盖）
├── static/index.html            # 网页版单文件前端
├── modules/
│   ├── auth_check.py            # 阶段1 准入校验 + SQLite
│   ├── collector.py             # 阶段2 采集（三道保护）
│   ├── ast_parser.py            # 阶段3a AST+正则+jsluice
│   ├── llm_analyzer.py          # 阶段3b LLM（防幻觉/降级）
│   ├── chain_builder.py         # 阶段4 链路组装
│   └── report_generator.py      # 阶段5 报告生成
├── utils/                       # logger / normalize / dedup
├── bin/                         # jsluice 多平台二进制（可选）
├── output/                      # 报告输出
├── Dockerfile / requirements.txt / README.md / LICENSE / build_exe.py
```

## 九、合规与免责声明

1. **使用者必须持有目标站点书面授权**，仅可用于合规安全审计、CTF/靶场演练、SDL 测试等授权场景；
2. 工具在**代码层面**禁止对提取 API 的网络请求（采集仅限同域公开静态资源，默认关闭跨域）；
3. 所有风险结论【静态源码推断，未实测】，实测由人工完成，使用者自负合规责任；
4. 开源协议：**AGPL-3.0**（核心引擎开源；提供 SaaS 服务时服务端源码需开放；闭源商用需改为私有商业协议）。
