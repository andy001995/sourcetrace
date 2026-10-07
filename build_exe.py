# build_exe.py
# PyInstaller 一键打包脚本（形态B：单文件 exe）
#
# 用法：
#   pip install pyinstaller
#   python build_exe.py
#
# 产物：dist/sourcetrace(.exe)
# 命令行：sourcetrace.exe --target http://xxx --output ./output/
import os
import pathlib
import sys

BASE_DIR = pathlib.Path(__file__).resolve().parent
os.chdir(BASE_DIR)


def main() -> None:
    try:
        import PyInstaller.__main__
    except ImportError:
        sys.exit("请先安装 PyInstaller：pip install pyinstaller")

    # 静态资源打包进可执行文件（--add-data 分隔符 Windows 用 ;，其他用 :）
    sep = ";" if os.name == "nt" else ":"

    args = [
        "main.py",                      # 入口（CLI）
        "--name", "sourcetrace",
        "--onefile",                    # 单文件
        "--console",                    # 控制台程序
        "--add-data", f"static{sep}static",
        "--hidden-import", "esprima",
        "--hidden-import", "httpx",
        "--hidden-import", "bs4",
        # 体积控制：排除用不到的重量级模块
        "--exclude-module", "matplotlib",
        "--exclude-module", "pandas",
        "--exclude-module", "PIL",
        "--exclude-module", "tensorflow",
        "--clean",
    ]

    print("正在打包 sourcetrace 单文件可执行程序 …")
    PyInstaller.__main__.run(args)
    print(f"完成！产物：{BASE_DIR / 'dist' / ('sourcetrace.exe' if os.name == 'nt' else 'sourcetrace')}")


if __name__ == "__main__":
    main()
