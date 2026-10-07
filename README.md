# 星巡 · 源链（SourceTrace）

![Release](https://img.shields.io/github/v/release/andy001995/sourcetrace)
![Stars](https://img.shields.io/github/stars/andy001995/sourcetrace)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-AGPL--3.0-green)

前端静态源码业务链路解析工具 · 零主动探测

---

## 这是什么

**星巡 · 源链（SourceTrace）** 是一个前端静态源码分析工具，用于渗透测试前期的信息收集。

它读取网站公开的 HTML/JS/配置文件，提取：

- API 接口路径
- 硬编码敏感信息（如 JWT_SECRET）
- 静态资源清单
- 业务交互链路

输出结构化 Markdown 报告，供**人工**进行后续验证。

**它不扫描、不发包、不爆破、不验证漏洞。**

---

## 使用场景

- 渗透测试前期：快速摸清目标的前端接口
- 授权资产审计：检查前端 JS 是否泄露敏感信息
- 自建靶场演练：验证渗透流程
- 学习训练：理解"业务交互链路"的思维方式

---

## 能做什么

- ✅ 提取前端 JS 里的 API 接口路径
- ✅ 识别硬编码密钥（如 JWT_SECRET）
- ✅ 区分静态资源和业务接口
- ✅ 支持 SPA（Vue/React）和传统 jQuery 网站
- ✅ tree-sitter 崩溃自动隔离，不中断任务
- ✅ 三种交付形态：CLI / 网页版 / Docker

## 不能做什么

- ❌ 不验证接口是否真实存在
- ❌ 不判断接口是否有漏洞
- ❌ 不检测前端框架版本
- ❌ 不支持需要登录才能看到的页面

---

## 安装

    git clone https://github.com/andy001995/sourcetrace.git
    cd sourcetrace
    pip install -r requirements.txt

---

## 使用

### CLI 模式

    python main.py --target https://目标站点 --output ./output/
    python main.py --target ./local_js --local --confirm --output ./output/

### 网页版

    uvicorn app:app --host 0.0.0.0 --port 8000

### Docker

    docker build -t sourcetrace .
    docker run -d -p 8000:8000 --name sourcetrace sourcetrace

---

## 技术架构

- AST 解析：tree-sitter（首选，子进程隔离）/ esprima（兜底）/ 正则（三保险）
- LLM 语义分析：可插拔，默认关闭
- 崩溃容错：tree-sitter 崩溃自动降级，不中断任务
- vendor 判定：文件名 + 内容双重判断

---

## 已知限制

本工具对以下 chunk 加载形式支持良好：

- 标准 script src 引用
- import 动态导入
- 模板字符串拼接的 JS 路径

以下形式当前不支持：

- webpack runtime 动态加载的 chunk
- 需要用户交互才加载的 chunk

对 webpack 打包的复杂 SPA，建议：

1. Chrome 打开目标站点
2. F12 → Network → 筛选 JS
3. 全选保存到本地目录
4. 用 --local 模式离线分析

---

## 作者与协作说明

本项目的产品定位、架构设计、模块拆分、边界定义、验收标准由作者主导完成。

代码实现阶段使用了 AI 编程助手辅助，作者承担了全部需求定义、方案决策、逐轮验收、缺陷定位与修复确认工作。

本项目采用 AGPL-3.0 协议开源，版权归 andy001995 所有。

---

## 边界与免责

本工具仅用于你拥有书面授权的目标。

使用者需自行承担合规责任。

所有输出标注【静态源码推断，未实测】。

---

## License

Copyright (c) 2026 andy001995

本项目采用 AGPL-3.0 协议开源。详见 LICENSE.
