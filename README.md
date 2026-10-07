# bin/ —— jsluice 可选增强二进制目录

## 这是什么
jsluice 是 BishopFox 开源的 Go 语言 JavaScript URL 提取器，可增强接口提取的
覆盖面（Webpack chunk、模板字符串、混淆代码等场景）。

本目录放多平台二进制后，程序会**自动识别系统并加载**，用户无感：
未放置二进制时，工具照常工作（AST + 正则双保险），只是少了这层增强。

## 命名规则（程序按此自动探测）
| 平台 | 文件名 |
| --- | --- |
| Linux x86_64 | `jsluice-linux-amd64` |
| Linux arm64 | `jsluice-linux-arm64` |
| macOS (Apple Silicon) | `jsluice-darwin-arm64` |
| macOS (Intel) | `jsluice-darwin-amd64` |
| Windows x86_64 | `jsluice-windows-amd64.exe` |

（系统 PATH 中已有的 `jsluice` 命令也会被自动识别。）

## 构建方法
需要 Go 1.21+：
```bash
go install github.com/BishopFox/jsluice@latest
# 交叉编译示例（Linux amd64）：
GOOS=linux GOARCH=amd64 go build -o bin/jsluice-linux-amd64 github.com/BishopFox/jsluice/cmd/jsluice
```

## 说明
- jsluice 仅在本机对**已下载的静态 JS 文件**做离线解析，不产生任何网络请求；
- 其结果并入接口清单时置信度标为「低（jsluice）」，与正则兜底同等对待；
- 程序会在 temp 目录写入临时文件供 jsluice 读取，用后即删。
