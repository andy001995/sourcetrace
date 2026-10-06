# VERIFICATION.md — 真实 GVL 静态文件 6 步验收记录

> 验收对象：gvl-recon 前端静态源码业务链路解析工具
> 输入数据：用户上传的真实 GVL 靶场前端静态文件 `gvl_static.tar.gz`（8 个文件，合计约 132KB）
> 验收时间：2026-10-06
> 验收原则：mock/自造数据不算数，全部以真实 JS 源码实测为准；不瞎编、不越界。

---

## 0. 验收结论总览

| # | 验收项 | 结果 | 说明 |
| --- | --- | --- | --- |
| 1 | collector.py 本地目录模式（零网络请求） | ✅ 通过 | `--target ./gvl_static --local` 直接读目录，日志确认"零网络请求" |
| 2 | 真实数据跑出 interfaces.json + report.md | ✅ 通过 | 15 条接口 / 15 条链路 / 报告落盘 |
| 3 | 覆盖率核对（6 个目标接口） | ⚠️ 5/6 命中 | 5 个接口从真实 JS 挖出；`POST /ai/chat` 在提供的 8 个文件中**无任何证据**（详见 3.7） |
| 4 | 硬编码密钥识别（JWT_SECRET='lab-secret'） | ✅ 通过 | 报告"硬编码敏感密钥"区块 + config.js 链路双重标注 |
| 5 | /config.js 去重（只出现 1 次） | ✅ 通过 | 无论引用次数，去重后 interfaces.json 中仅 1 条 |
| 6 | 输出本 VERIFICATION.md | ✅ 通过 | 本文件 |

---

## 1. 第 1 步：collector.py 本地目录模式

**改动**：`modules/collector.py` 新增本地目录模式——target 为本地路径（或显式 `--local`）时，
直接递归读取目录下 HTML/JS/配置，零 HTTP 请求；与网络模式共用同一套 HTML 解析、
动态 chunk 发现、三道保护（单文件 2MB / 递归 10 层 / 总数 500）逻辑。
`main.py` 新增 `--local` 参数并支持本地路径自动识别（不再补 https:// 协议）。

**实测命令**：

```bash
python main.py --target ./gvl_static/gvl_static --local --confirm --llm-provider off --output ./output/
```

**实测输出（关键日志）**：

```
[INFO] ===== 本地目录模式 target=.../gvl_static/gvl_static（零网络请求） =====
[WARNING] [本地模式] 缺失 chunk/资源: /assets/index-BCn5QfZZ.js   （共 7 个，容忍并记录）
[INFO] 采集完成（本地目录）：JS 7 个，HTML资源引用 4 条，缺失 chunk 7 个
```

**验证点**：
- ✅ 无任何 HTTP 请求（日志明文标注"零网络请求"；本地模式下未触发任何网络请求）；
- ✅ 三层防护生效（本批文件均未超限，缺失 chunk 被容忍记录而非中断）；
- ✅ 双层目录嵌套 `gvl_static/gvl_static/` 与 HTML 中 `/assets/index-CAJbFedo.js` 的目录前缀差异
  均通过"URL 路径直查 → basename 全树唯一匹配"兜底正确解析。

---

## 2. 第 2 步：真实数据端到端运行

**命令**（用户指定形态 + 授权交互）：

```bash
echo y | python main.py --target ./gvl_static --local --output ./output/
```

**产物**（均落盘并核对）：

| 产物 | 结果 |
| --- | --- |
| `output/raw_js/` | ✅ 原始 JS 备份（7 个 JS 文件全部备份） |
| `output/interfaces.json` | ✅ 15 条接口 + meta（secrets / missing_chunks / local_mode） |
| `output/chains.json` | ✅ 15 条业务链路 |
| `output/report.md` | ✅ Markdown 报告（概览 + 链路详情 + 密钥区块 + 缺失 chunk + 统计） |

---

## 3. 第 3 步：覆盖率核对（6 个目标接口）

interfaces.json 中逐条核对的最终结果：

| 目标接口 | 方法 | 状态 | 来源文件（真实证据） | 提取方式 |
| --- | --- | --- | --- | --- |
| /api/admin/spel/eval | POST | ✅ 命中 | DataImport-ByrwMFl_.js | 封装函数链路（`n("/api/admin/spel/eval",{expression})`） |
| /api/admin/xml/parse | POST | ✅ 命中 | DataImport-ByrwMFl_.js | 封装函数链路（`n("/api/admin/xml/parse",{xml})`） |
| /api/admin/file/import | POST | ✅ 命中 | DataImport-ByrwMFl_.js | 封装函数链路（`n("/api/admin/file/import",{url,classname})`） |
| /ai/session/detail | GET | ✅ 命中 | AIChat-B5AfZW2N.js | 通用 member 调用（`u.get("/ai/session/detail",{params:{id}})`） |
| /ai/chat | POST | ⚠️ 未命中 | 提供的 8 个文件中不存在 | —（见 3.7） |
| /config.js | GET | ✅ 命中 | index.html `<script src="/config.js">` | 静态资源条目（含 JWT_SECRET 关联） |

> 置信度说明：本批真实文件为 Vue3 压缩产物，环境内 esprima(4.0.1) 无法整体解析（可选链/大对象等语法），
> 工具已实现「语法容错预处理 + 分块解析降级」；上表接口均由**源码字符串字面量直接命中**的正则兜底
> （封装函数链路识别 / 通用 member 调用识别）捕获，出处明确、无编造，按产品置信度规则标注"低（正则兜底）"。

### 3.7 POST /ai/chat 缺失说明（如实记录，不编造）

对全部 8 个上传文件做了**全量字面量搜索、拼接形式搜索、模板字符串搜索**（`"/ai/"`、`chat`、`/ai/chat`
及其变体），**未发现任何 /ai/chat 证据**。已发现的相关证据：

- 同文件（AIChat-B5AfZW2N.js）存在 AI 会话接口簇：`GET /ai/session/list`、`POST /ai/session/create`、`GET /ai/session/detail`；
- 该文件 import 了 `./index-BCn5QfZZ.js`（axios 封装模块）与 `./index-BeuR1rjS.js`，**这两个文件不在上传包内**；
- 报告"未解析的 chunk"区块已列出全部 7 个缺失文件（index-BCn5QfZZ.js、Search-CCao8idP.js 等）。

**结论**：`/ai/chat` 大概率位于缺失 chunk 中（如 AI 会话的聊天组件）。本工具遵守"不瞎编"铁律，
**不会伪造该条目**；补齐缺失文件后重跑即可纳入。若您的靶场确有该接口，请确认前端包是否完整。

---

## 4. 第 4 步：硬编码密钥识别（JWT_SECRET='lab-secret'）

**源码证据**：`config.js` 第 3 行 `const JWT_SECRET = 'lab-secret'`（另 `window.JWT_SECRET = JWT_SECRET`）。

**识别结果**（report.md "附：硬编码敏感密钥"区块 + config.js 链路双重标注）：

```markdown
| JWT_SECRET | lab-secret | /config.js:3 | 硬编码敏感密钥，若服务端直接信任该值，
可能导致认证绕过、会话伪造或越权；是否可利用需人工实测确认 |
```

config.js 业务链路"静态推导风险"追加：

```
- 来源文件含硬编码敏感密钥（JWT_SECRET=lab-secret）【静态源码推断，未实测】
```

**额外真实发现**：`app.js` 中 `TEST_ACCOUNT = { user:'alice', pass:'alice123' }` 被识别为
硬编码测试凭据（pass=alice123），一并进入密钥区块（同为源码字面量直接命中）。

---

## 5. 第 5 步：/config.js 去重验证

- `index.html` 实际引用 `/config.js` **1 次**（用户描述"多次引用"，以真实数据为准：仅 1 次）；
- 无论引用次数多少，接口清单经「URL 归一化 + (方法,URL) 去重」后，interfaces.json 中 `/config.js` **恰好 1 条**：

```bash
/config.js 出现次数: 1   # 实测输出
```

---

## 6. 环境与限制说明（如实披露）

| 项 | 说明 |
| --- | --- |
| Python | 3.12.11 |
| AST 解析器 | acorn-python（PyPI 无可用实现）→ esprima 4.0.1（实际生效）→ 分块解析降级 + 正则兜底 |
| 硬编码密钥扫描 | 新增（键名白名单 + 占位值剔除），本批命中 2 处 |
| 置信度规则 | 高=AST 命中 / 中=LLM 推断 / 低=正则兜底（本批接口因压缩产物 AST 兼容性受限多为"低"，但均有字符串字面量直接出处） |
| 边界铁律 | 全程零 API 发包：本地模式零网络请求；输出风险一律标注【静态源码推断，未实测】 |

---

## 7. 二次验收（补齐 6 个缺失 chunk，14 文件）

用户补传了缺失的 JS chunk（共 14 个文件）：

- **本次新增文件（6 个，均实际存在）**：index-BCn5QfZZ.js / Login-B6ZVb2aX.js /
  Order-XsLI0mJH.js / Profile-AMgzS-60.js / Search-CCao8idP.js / JobList-C0UThXgJ.js
- **引用但不存在（1 个）**：index-BeuR1rjS.js —— JS 中声明了对它的 `import()`，
  但该文件实际未提供/不存在（已 grep 验证），故无法解析其内容，相关调用不计入提取结果。

并集成 **tree-sitter 错误容忍解析器**（首选 AST 引擎）后重新验收：

### 7.1 index-BCn5QfZZ.js 确认

头部为 Vue 运行时工具函数，但全文含 `axios`×2、`baseURL`×4、`interceptors`×3、`.get(`×5、
`.delete(`×5、`create(`×13 —— **确认是 axios 封装层**（接口基础 URL 与拦截器定义处）。

### 7.2 接口提取结果（补齐后）

| 指标 | 上一版（8 文件） | 本版（14 文件 + tree-sitter） |
| --- | --- | --- |
| 接口总数 | 15 条 | **23 条** |
| AST 高置信 | 0 条 | **20 条**（↑ 覆盖率显著提升） |
| 正则/资源低置信 | 15 条 | 3 条（均为 HTML 资源引用条目） |
| 缺失 chunk | 7 个 | 1 个（仅 CSS /assets/index-DpRJX-5H.css） |
| 解析器 | AST(esprima) | **AST(tree-sitter)** |

新增接口（均为 AST 高置信，源码字面量直接命中）：`/auth/login`、`/order/list`、`/order/detail`、
`/order/verify`、`/user/profile`(GET/PUT)、`/api/admin/job/list`、`/api/admin/job/update`。

### 7.3 目标接口核对（本版）

| 目标接口 | 方法 | 状态 | 提取方式（置信度） |
| --- | --- | --- | --- |
| /api/admin/spel/eval | POST | ✅ | 封装函数链路 ast_wrapper（高） |
| /api/admin/xml/parse | POST | ✅ | 封装函数链路 ast_wrapper（高） |
| /api/admin/file/import | POST | ✅ | 封装函数链路 ast_wrapper（高） |
| /ai/session/detail | GET | ✅ | member 调用 ast（高） |
| /ai/chat | POST | ⚠️ 仍缺失 | **14 个文件均无任何证据**（字面量/拼接/模板全量搜索） |
| /config.js | GET | ✅ | 资源条目（低，含 JWT_SECRET 关联） |

### 7.4 /ai/chat 二次确认（如实记录）

对补齐后的全部 14 个文件再次做全量搜索（`chat`、`"/ai`、`/ai/chat`、拼接/模板变体），
**仍未发现任何 /ai/chat 证据**。AI 相关接口在该批次中仅存在会话簇：
`GET /ai/session/list`、`POST /ai/session/create`、`GET /ai/session/detail`。
若靶场确有此接口，其调用代码应位于未提供的前端模块或由服务端下发配置驱动；
本工具遵守"不瞎编"铁律，不伪造条目。

### 7.5 硬编码密钥与去重（本版）

- `JWT_SECRET=lab-secret`：✅ 密钥区块（/config.js:3）+ config.js 链路双重标注，未受解析器更换影响；
- `/config.js` 在 interfaces.json 中：✅ 恰好 1 条（去重不变）。

*二次验收结论：接口提取与 AST 覆盖率随数据补齐与解析器升级显著提升；/ai/chat 缺失为数据事实，如实记录。*

---

## 8. 三次验收（LLM 可插拔改造 + 关键词规则误判修正）

本次测试环境无可用 LLM 通道，因此未产生真实 LLM 输出；LLM 已改为可插拔可选功能，用户在自己环境配置 Key 后即可一键启用。

### 8.2 LLM 改为可插拔设计（默认关闭，配 Key 才启用）

- `config.py`：`LLM_PROVIDER` 默认由 `off` 改为 **`auto`**，并在注释中写明启用方法；
- `llm_analyzer.py`：新增 `_resolve_provider()` 可插拔判定，判定矩阵实测如下：

| 配置 | 实际生效 | 实测 |
| --- | --- | --- |
| `auto` + 无 Key | `off`（零 LLM 请求，走关键词规则） | ✅ |
| `auto` + 有 Key | `openai`（自动启用） | ✅ |
| `openai` + 无 Key | 安全降级 `off`（**绝不带空 Key 发包**） | ✅ |
| `openai` + 有 Key | `openai` | ✅ |
| `ollama` | `ollama`（连本机，不依赖 Key） | ✅ |
| `mock` / `off` | 原样 | ✅ |

- 报告与链路文案：所有"未启用 LLM 语义分析"改为
  **"LLM 语义分析未启用（可选），漏洞类型映射基于关键词规则，准确率有限，建议配置 LLM 后重跑"**；
- `main.py` CLI `--llm-provider` 增加 `auto` 选项；`app.py` 网页版不传 provider 时同样默认 auto（无 Key 自动关闭）；
- README 第六章重写：说明 LLM 为可选功能、auto 判定逻辑、OpenAI 兼容/Ollama 启用步骤。

### 8.3 关键词规则误判修正（默认模式即受益，不依赖 LLM）

| 接口 | 修正前 | 修正后 | 根因/修法 |
| --- | --- | --- | --- |
| GET/PUT /user/profile | 文件族·任意文件读取（**误判**） | 未知族·需人工研判 | 子串匹配把 pro**file** 当 "file"；改为 ASCII 词**单词边界**匹配 |
| POST /api/admin/xml/parse | 权限族·越权（漏报 XXE） | **注入族·XML 外部实体注入（XXE）** | 新增 XXE 规则并置于 admin 泛规则之前 |
| GET /api/admin/template/render | 权限族·越权（漏报 SSTI） | **注入族·服务端模板注入（SSTI）** | 新增 SSTI 规则并前置 |
| PUT /api/admin/job/update | 注入族·SQL 注入（**新发现误报**） | 权限族·越权 | 裸词 update 误伤 REST 更新路径；SQL 规则收紧为 sql/jdbc 等强信号 |

规则按"特异性从高到低"重排（表达式注入/XXE/SSTI/命令注入/SQLi → 文件 → 认证 → 权限 → 暴露面），
所有映射仍为【静态源码推断，未实测】提示，最终判定权在人工。

### 8.4 核心结果不回退回归

以默认配置（`auto` + 无 Key → 关闭 LLM）重跑 14 个真实文件：

- 接口总数 **23**；AST 高置信 **20**、正则/资源低置信 **3**（与二次验收一致，未回退）；
- 硬编码密钥 **2 处**（含 `JWT_SECRET=lab-secret`）；`/config.js` 去重仍为 **1** 条；
- 全部 Python 文件 `py_compile` 通过；本地模式零网络请求。

### 8.5 如何在有 LLM 的环境复现"LLM 启用前后对比"（交付给使用者的操作）

```bash
# 启用前（关键词规则，本轮默认产物 report.md 即此状态）
python main.py --target ./gvl_static --local --confirm --output ./output_rules/

# 启用真实 LLM（OpenAI 兼容；DeepSeek/通义/智谱/Kimi 等均可）
export LLM_PROVIDER=openai LLM_API_KEY=sk-xxx \
       LLM_BASE_URL=https://api.deepseek.com/v1 LLM_MODEL=deepseek-chat
python main.py --target ./gvl_static --local --confirm --output ./output_llm/
diff <(grep -E '业务起点|族：' output_rules/report.md) \
     <(grep -E '业务起点|族：' output_llm/report.md)
```
LLM 启用后会额外填充接口业务功能/分层/调用依赖（schema 见 `llm_analyzer.py`），
且防幻觉归一化保证：清单之外的接口、参数一律丢弃，解析失败自动降级回关键词规则结果。

---

## 9. 四次验收（修复 tree-sitter Segmentation fault：子进程隔离）

### 9.1 问题

用户本地跑 CLI，日志在"识别到封装函数 15 个"后出现 `Segmentation fault (core dumped)`。
根因：tree-sitter 是 C 扩展，解析某个 JS 文件时触发段错误，进程被内核直接杀死，
**Python 的 try/except 无法捕获**，导致整个任务终止。

### 9.2 修复（进程隔离 + 超时 + 自动降级）

- 每个文件的 tree-sitter 解析放进 **`multiprocessing` spawn 独立子进程**（模块级 worker `_ts_worker`），
  子进程通过 Pipe 回传提取出的接口记录；
- 主进程 `proc.join(TS_FILE_TIMEOUT)`（默认 30s，可环境变量覆盖）：
  - 正常（exitcode=0）→ 合并结果；
  - 超时（exitcode=None）→ `kill()` 子进程，记录超时；
  - 崩溃（exitcode 为负，SIGSEGV=-11）→ 记录信号名；
- 崩溃/超时/异常的文件**自动降级为纯 Python 的 esprima 解析**（含正则兜底），
  并收集到 `crashed_files`，写入 interfaces.json meta 与 report.md 专表；
- **一个文件崩溃只杀死对应子进程，主进程与其他文件解析不受影响**；
- main.py 加 `multiprocessing.freeze_support()`（PyInstaller + spawn 兼容）；app.py 网页版同步透传；
- 补齐 `modules/__init__.py`、`utils/__init__.py`（包标记，含一行注释）。

### 9.3 实测结果（用户指定命令与路径）

命令：`python3 main.py --target /tmp/gvl_static --local --confirm --output ./output_test/`

- 任务**全程无 Segmentation fault**，退出码 0；
- `output_test/` 4 个产物齐全：`raw_js/`（13 个备份）、`interfaces.json`、`chains.json`、`report.md`；
- 结果不回退：23 接口 / AST 高置信 20 / 硬编码密钥 2 处 / /config.js 去重 1。

### 9.4 隔离机制主动验证（不止"这次没崩"）

| 失败路径 | 注入方式 | 实测结果 |
| --- | --- | --- |
| 子进程超时 | `TS_FILE_TIMEOUT=0.001` | 主进程 kill 子进程、记录超时、判定需降级（False）✅ |
| 子进程 SIGSEGV | 子进程 `ctypes.string_at(0)` | exitcode=**-11（SIGSEGV）**，主进程存活、记录崩溃并降级 ✅ |

证明：真实 tree-sitter 段错误发生时，主进程能捕获信号退出码、自动降级、继续其余文件，任务不中断。

---

*本验收记录全部结论基于真实上传文件实测；任何未在文件中出现的接口均未编造。*
