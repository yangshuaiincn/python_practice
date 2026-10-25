#!/usr/bin/env python
# coding:utf-8
# @Time    : 2026/10/13 22:02
# @Author  : yangshuai
# @Site    : 
# @File    : diskusecheck.py
# @Software: PyCharm 
# @Comment : 扫描指定目录（默认 `/var/log`）下所有超过 **100MB** 的文件，输出表格化报告（路径、大小、最后修改时间），并按大小降序排列
"""
### 🟢 阶段一：系统信息探测与文件处理
> **目标**：掌握 `os`/`pathlib`、文件读写、字符串解析，建立"脚本即工具"的思维。

#### 题目：磁盘空间巡检器
编写一个脚本，扫描指定目录（默认 `/var/log`）下所有超过 **100MB** 的文件，输出表格化报告（路径、大小、最后修改时间），并按大小降序排列。若目录不存在或无权限，需优雅提示而非崩溃。

**核心考点**：
-   `pathlib.Path.rglob()` 递归遍历
-   文件大小的人类可读格式化（B/KB/MB/GB）
-   异常捕获（`PermissionError`, `FileNotFoundError`）
-   命令行参数解析（`argparse` 支持自定义目录和阈值）

**进阶挑战**：增加 `--delete` 参数，交互式确认后删除匹配文件；增加 `--output report.csv` 导出功能。
"""
# 使用east_asian_width获取中文的实际显示位数
# from unicodedata import east_asian_width
# 使用argparse解析执行脚本时的传参
import argparse
# 使用os.remove删除指定文件
# 选择导出结果为CSV文件
import csv
# 使用pathlib.path.rglob方法，递归获取指定目录下的内容，不区分操作系统
import pathlib
# 判断脚本运行时的操作系统类型
import platform
# 使用re匹配传入的参数中数字和单位，以便进行换算
import re
# 使用datetime函数，将获取到的修改时间格式化输出
from datetime import datetime

from rich.console import Console
from rich.table import Table

default_directory_win = r"D:\images"
default_directory_linux = "/var/log"
default_file_minsize = "100K"


# 参数解析
def parse_args():
    parser = argparse.ArgumentParser(
        prog="File Scanner",
        description="扫描指定目录（默认 `/var/log`）下所有超过指定大小的文件，并按指定顺序排列",
        epilog="示例：diskusecheck -d /var/log -s 100M --delete --output=diskusecheck.csv",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-d", "--dict",
        type=str,
        help="扫描目录，默认为/var/log"
    )

    parser.add_argument(
        "--delete",
        # 当命令行出现--delete时，arg.delete自动为true
        action="store_true",
        help="是否开启交互式删除模式"
    )

    parser.add_argument(
        "-s", "--size",
        type=str,
        default=default_file_minsize,
        help="指定查找超过该大小的文件"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        help="导出查找结果为CSV文件,存放在执行路径下"
    )

    return parser.parse_args()


# 人性化显示文件大小函数，以1024为进位
def human_Filesize(size: int) -> str:
    s = int(size)
    if s < 0:
        return "0 B"
    elif 0 <= s < 1024:
        return f"{s:.2f}B"
    elif 1024 <= s < (1024 ** 2):
        return f"{s / 1024:.2f}KB"
    elif (1024 ** 2) <= s < (1024 ** 3):
        return f"{s / (1024 ** 2):.2f}MB"
    elif (1024 ** 3) <= s < (1024 ** 4):
        return f"{s / (1024 ** 3):.2f}GB"
    elif (1024 ** 4) <= s < (1024 ** 5):
        return f"{s / (1024 ** 4):.2f}TB"


# 传入的查找最小值解析为纯数字（B为单位）
def parse_Size(s: str) -> int:
    s = s.strip().upper()
    match = re.match(r'^(\d+(?:\.\d+)?)\s*(B|K|KB|M|MB|G|GB|T|TB)?$', s)
    if not match:
        raise ValueError(f"无法解析文件大小：{s},格式示例：1kb、8.88Mb、0.9tB")
    value = float(match.group(1))
    unit = match.group(2) or 'B'
    units = {"B": 1, "K": 1024, "KB": 1024, "MB": 1024 ** 2, "M": 1024 ** 2, "G": 1024 ** 3, "GB": 1024 ** 3,
             "T": 1024 ** 4,
             "TB": 1024 ** 4, "P": 1024 ** 5, "PB": 1024 ** 5}
    result = value * units[unit]
    if result < 0:
        raise ValueError("文件大小不能为负数")
    return result


# 根据输入目录，获取该目录下大小大于 file_maxsize 的文件，并按指定文件大小倒序打印文件路径，大小，修改时间
def dir_Check(path, max_file_size) -> list[dict[str, str, str]]:
    filelist = []
    if not path.exists():
        print(f"指定目录：{path}不存在！")
        return []
    if not path.is_dir():
        print(f"指定目录：{path}不是目录！")
        return []
    rg = path.rglob('*')
    while True:
        try:
            file = next(rg)
        except PermissionError as e:
            print(f"跳过无权限路径：{e.filename}")
            continue
        except StopIteration:
            break
        else:
            if file.is_file():
                filestat = file.stat()
                if int(filestat.st_size) > max_file_size:
                    filelist.append(
                        {"filename": str(file), "filesize": filestat.st_size,
                         "mtime": filestat.st_mtime})
    filelist.sort(key=lambda x: x["filesize"], reverse=True)
    # 将stat()返回的文件大小和修改时间改为符合人类阅读习惯的格式
    for f in filelist:
        f["filesize"] = human_Filesize(f["filesize"])
        f["mtime"] = datetime.fromtimestamp(f["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
    return filelist


def safe_delete(filelist) -> bool:
    for file in filelist:
        filename = file["filename"]
        fileszie = file["filesize"]
        print(f"\n您即将删除：{filename}，大小：{fileszie},是否确认？")
        result = input("(输入exit退出)")
        if result.upper() == "EXIT":
            print("退出删除流程")
            return False
        elif result.upper() not in ("y", "Y", "YES", "Yes"):
            print("您未确认删除，进行下个文件删除\n")
            continue
        # os.remove(f["filename"])
        print(f"成功删除：{filename},大小：{fileszie}\n")
        continue
    print(f"您已完成本次删除，程序退出")
    return True


def export_CSV(filelist: list, csvname: str) -> bool:
    if csvname.upper().endswith(".CSV"):
        csvname = csvname[:-3]
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    csvname = f"{csvname}{now}.csv"
    with open(csvname, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "filesize", "mtime"])
        writer.writeheader()
        writer.writerows(filelist)
        print(f"\n{csvname}已写入")
        return True


if __name__ == '__main__':
    args = parse_args()
    # 判断是否自定义扫描目录，否则配置默认扫描路径（根据操作系统区分）
    if args.dict is None:
        plat = platform.system()
        if plat == "Windows":
            dir_path = pathlib.Path(default_directory_win)
        else:
            dir_path = pathlib.Path(default_directory_linux)
    else:
        dir_path = pathlib.Path(args.dict)

    fl = dir_Check(path=pathlib.Path(dir_path), max_file_size=parse_Size(args.size))
    if not fl:
        print("未找到符合的文件，程序退出")
        exit(1)
    table = Table(title="文件大小筛查")

    table.add_column("文件名", justify="left", style="cyan", no_wrap=True)
    table.add_column("大小", style="magenta")
    table.add_column("修改时间", justify="right", style="green")
    for f in fl:
        table.add_row(f["filename"],f["filesize"],f["mtime"])
    console = Console()
    console.print(table)
    # 测试输出CSV文件
    if args.output is not None:
        export_CSV(fl, args.output)
    # 判断是否交互删除
    if args.delete:
        safe_delete(fl)
    exit(0)
