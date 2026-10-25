#!/usr/bin/env python
# coding:utf-8
# @Time    : 2026/10/15 14:11
# @Author  : yangshuai
# @Site    :
# @File    : nginx_log_analyzer.py
# @Software: PyCharm
# @Comment :
"""
编写一个 Python 脚本 nginx_log_analyzer.py，解析 Nginx 默认格式的访问日志，输出以下统计信息：
Top 5 访问 IP（按请求次数降序）
Top 5 请求路径（按请求次数降序）
HTTP 状态码分布（各状态码的请求数及占比）
每小时请求量趋势（仅展示有数据的时段）
可选进阶：导出 CSV / 识别异常高频 IP（如单 IP > 1000次/小时）
支持 gzip 压缩日志（`gzip.open`）；增加 `--since "2026-10-13 10:00"` 时间过滤
"""

"""
标准 Nginx combined 格式access.log 各字段解析
$remote_addr	192.168.1.100	客户端真实 IP。⚠️ 若 Nginx 前有 CDN/WAF/LB，此处为代理节点 IP，需改用 $http_x_forwarded_for 或 $realip_remote_addr
-	-	占位符，对应 $remote_user。仅当启用 Basic Auth 认证时才有值，否则恒为 -
$remote_user	-	HTTP Basic Auth 用户名。99% 的现代 API 服务此字段无用
$time_local	[15/Oct/2026:21:30:45 +0800]	服务器本地时间。注意格式含时区偏移，日志分析工具（如 GoAccess、ELK）依赖此时区做时间对齐
$request	"GET /api/v1/users?id=10 HTTP/1.1"	完整请求行 = Method + URI + Protocol。⚠️ URI 包含查询参数，可能含敏感信息（token/password），生产环境建议脱敏
$status	200	HTTP 响应状态码。监控核心指标：5xx 告警、4xx 排查、301/302 追踪重定向链
$body_bytes_sent	1234	响应体大小（字节）。不含响应头。值为 0 表示空 body（如 204/304）。⚠️ 不是 $bytes_sent（后者含 header）
$http_referer	"https://example.com/..."	来源页面。用于流量归因分析。值为 - 表示直接访问/书签/API调用/隐私浏览器
$http_user_agent	"Mozilla/5.0 ..."	客户端标识。用于设备/浏览器统计、爬虫识别、异常 UA 拦截
"""

# 使用argparse解析执行脚本时的传参
import argparse
# 导出结果为CSV
import csv
# 解析gzip压缩文件
import gzip
# 判断操作系统类型
import platform
# 使用re匹配Nginx combined 格式access.log 各字段
import re
# 匹配到的结果写入sqlite3内存数据库
import sqlite3
# 匹配的日期转换
from datetime import datetime, timedelta
# 使用path扫描目录下accesslog文件
from pathlib import Path

# 使用east_asian_width获取中文的实际显示位数
from unicodedata import east_asian_width

# 默认存入数据库表名
table_name = "formated_access_log"
# 默认时区+8 区
default_timezone = 8
# 默认查找一周内日志
default_search_hour = 168


# accesslog各字段匹配规则
pattern_remote_addr = "^(?P<remote_addr>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) "
pattern_remote_user_Auth = "(?P<remote_user_Auth>\S+) "
pattern_remote_user = "(?P<remote_user>\S+) "
pattern_time_local = "\[(?P<time_local>\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "
pattern_quest_method = "\"(?P<quest_method>[A-Z]+) "
pattern_quest_URI = "(?P<quest_URI>/\S*) "
pattern_quest_protocol = "(?P<quest_protocal>[a-zA-Z]+/\d+\.\d+)\" "
pattern_status = "(?P<status>\d{3}) "
pattern_body_bytes_sent = "(?P<body_bytes_sent>\d+) "
pattern_http_referer = "\"(?P<http_referer>.+)\" "
pattern_http_user_agent = "\"(?P<http_user_agent>.*)\"$"

log_parser = re.compile(
                pattern_remote_addr + pattern_remote_user_Auth + pattern_remote_user + pattern_time_local +
                pattern_quest_method + pattern_quest_URI + pattern_quest_protocol + pattern_status +
                pattern_body_bytes_sent + pattern_http_referer + pattern_http_user_agent)

# 使用数据库查询需要的统计信息SQL
# sql_top5_ip = f"select * from {table_name}"
sql_top5_ip = f"select remote_addr as '访问IP',count(remote_addr) as '访问次数' from {table_name} " \
              f"group by remote_addr order by count(remote_addr) desc limit 5"

sql_top5_request = f"select quest_URI as '请求路径',count(quest_URI) as '请求次数' from {table_name} " \
                   f"group by quest_URI order by count(quest_URI) desc limit 5"

sql_httpcode_status = f"select status as 'http状态码',count(status) as '请求次数', " \
                      f"count(status)*100/(select count(1) from {table_name}) as '请求数占比'  " \
                      f"from {table_name} group by status order by count(status) desc"

sql_everyhour_questcount = f"select strftime('%Y/%m/%d %H:00:00',time_local) as '时间',count(1) as '数量' from " \
                           f"{table_name} group by strftime('%Y%m%d%H',time_local)  having count(1)>0 " \
                           f"order by strftime('%Y%m%d%H',time_local) asc"

sql_high_freq_ips = f"select remote_addr as '访问IP',strftime('%Y%m%d%H',time_local) as '时间'," \
                    f"count(remote_addr) as '访问次数' from {table_name} group by strftime('%Y%m%d%H',time_local) " \
                    f"having count(remote_addr)>2 order by count(remote_addr) desc"


# 参数解析
def parse_args():
    parser = argparse.ArgumentParser(
        prog="Nginx Log Analyzer",
        description="解析 Nginx 默认格式的访问日志",
        epilog='示例：nginx_log_analyzer.py -d /var/log/nginx/ -A -s "2026-10-13 10:00" --output=nginx_log_analyzer.csv',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-d", "--directory",
        type=str,
        help="扫描目录，默认为/var/log/nginx"
    )

    parser.add_argument(
        "-A", "--all",
        action="store_true",
        help=r"是否扫描该目录下所有accesslog（包含gz压缩日志），默认只扫描access.log"
    )

    parser.add_argument(
        "-s", "--since",
        type=str,
        help="过滤指定时间前的数据"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        help="导出查找结果为CSV文件,存放在执行路径下"
    )

    return parser.parse_args()


# 初始化数据库，创建表格用于装填日志信息
def init_db(table_name: str):
    conn = sqlite3.connect(":memory:")
    print("数据库打开成功")
    c = conn.cursor()
    sql = f"""Create table {table_name}
    (
     remote_addr TEXT,
     remote_user_Auth TEXT,
     remote_user TEXT,
     time_local TEXT,
     quest_method TEXT,
     quest_URI TEXT,
     quest_protocol TEXT,
     status TEXT,
     body_bytes_sent TEXT,
     http_referer TEXT,
     http_user_agent TEXT
    );
    """
    # print(sql)
    c.execute(sql)
    print(f"建表{table_name}成功")
    conn.commit()
    return conn



# 根据sql语句查询数据（第一行返回字段名）
def query_db(conn, sql):
    list_title = []
    list_body = []
    cur = conn.cursor()
    cursor1 = cur.execute(sql)
    for i in range(0, len(cursor1.description)):
        list_title.append(cursor1.description[i][0])
    list_body.append(list_title)
    for row in cursor1:
        # print(row)
        list_body.append(list(row))
    return list_body


# 关闭数据库连接
def close_db(conn):
    conn.close()
    return True


# 判断实际显示宽度（非英文实际显示2位）
def view_Length(s: str) -> int:
    count = 0
    for item in s:
        res = east_asian_width(item)
        if res in ('W', 'F', 'A'):
            count += 2
        else:
            count += 1
    return count


# 根据每列最大宽度，使用空格补全，使显示对齐
def view_Display(s: str, maxlen: int) -> str:
    padding = max(0, (maxlen - view_Length(s)))
    return s + " " * padding


# 根据sql返回结果（带字段名），逐行对齐打印到终端
def show_SQL_result(input_sql):

    query_list = query_db(c, input_sql)
    # col_with 返回 [[1,2],[3,4]]格式列表中每列的最大宽度
    col_with = [max(view_Length(str(item)) for item in col) for col in zip(*query_list)]

    list_show = ""
    for x in range(0, len(query_list)):
        for y in range(0, len(query_list[x])):
            list_show = list_show + view_Display(str(query_list[x][y]), col_with[y]) + " "
        print(list_show)
        list_show = ""



# 判断是否是gzip压缩文件
def is_zipfile(file_full_name: str) -> bool:
    try:
        with open(f"{file_full_name}", mode="rb") as f:
            magic = f.read(2)
    except (OSError, IOError):
        return False
    if magic == b"\x1f\x8b":
        return True
    else:
        return False


# 判断输入的日期是否符合要求
def is_formated_time(inputtime: str) -> bool:
    try:
        datetime.strptime(inputtime, "%Y/%m/%d %H:%M:%S")
        return True
    except (ValueError, TypeError):
        return False


# 解析根据写好的解析规则解析文件，并逐行插入数据库，每1000条提交一次
def scan_file(file_full_name: str, c_time, c) -> bool:
    # 打印文件行数用
    num_lines = 1
    batch_data = []
    open_func = gzip.open if is_zipfile(file_full_name) else open
    mode = "rt" if is_zipfile(file_full_name) else "r"
    with open_func(f"{file_full_name}", mode=mode, encoding="utf-8") as f:
        for line in f:
            match_g = log_parser.match(line)
            if match_g is None:
                print(f"解析不到此行数据：{line}")
                num_lines += 1
                continue
            r_list = list(match_g.groups())
            dt = datetime.strptime(r_list[3], "%d/%b/%Y:%H:%M:%S %z")
            r_list[3] = dt.astimezone().replace(tzinfo=None).isoformat()
            if r_list[3] >= c_time.isoformat():
                batch_data.append(r_list)
                print(f"解析第{num_lines}行数据成功")
            # 每1000行数据提交一次数据库
            num_lines += 1
            if len(batch_data) >= 1000:
                c.executemany(f"insert into {table_name} values({','.join('?' * 11)})",batch_data)
                c.commit()
                batch_data.clear()
    if batch_data:
        c.executemany(f"insert into {table_name} values({','.join('?' * 11)})",batch_data)
        c.commit()

    return True


# 导出结果为CSV文件
def export_CSV(filelist: list, csvname: str) -> bool:
    if csvname.upper().endswith(".CSV"):
        pass
    else:
        csvname = f"{csvname}.csv"
    csvname = f"{csvname}.csv"
    with open(csvname, "a", newline="", encoding="utf-8-sig") as f:
        # writer = csv.DictWriter(f, fieldnames=filelist[0])
        # writer.writeheader()
        # writer.writerows(filelist[1:])
        writer = csv.writer(f)
        writer.writerows(filelist)
        print(f"\n{csvname}已写入")
        return True


if __name__ == '__main__':
    # 判断操作系统
    if platform.system() == "Windows":
        # default_logdir = r'C:\nginx\logs'
        default_logdir = r'C:\Users\84109\PycharmProjects\myProject'
        fengefu = '\\'
    else:
        # default_logdir = r'/usr/log/nginx'
        default_logdir = r'/home/ys'
        fengefu = '/'

    args = parse_args()
    # 判断是否指定目录，否则使用默认目录（根据操作系统划分）
    if not args.directory:
        real_dir = default_logdir
    else:
        real_dir = args.directory
    # 判断是否指定比较时间，否则默认读取一周内数据
    compare_time = args.since
    if is_formated_time(args.since):
        compare_time = datetime.strptime(args.since, "%Y/%m/%d %H:%M:%S")
    else:
        print(f"未输入时间或输入时间有误，默认获取当前时间-{default_search_hour} 小时内容")
        compare_time = datetime.now() - timedelta(hours=default_search_hour)
    print(compare_time)

    # 初始化数据库
    c = init_db(table_name)

    # 判断是否解析当前目录下所有accesslog，否则只解析access.log
    if not args.all:
        file_full_name = real_dir + fengefu + 'access.log'
        print(file_full_name)
        scan_file(file_full_name, compare_time, c)
    else:
        rg = Path(real_dir).rglob('access.log*')
        while True:
            try:
                real_file = str(next(rg))
                print(real_file)
                scan_file(real_file, compare_time, c)
            except StopIteration:
                break

    print("\nTop 5 访问 IP（按请求次数降序）:\n")
    show_SQL_result(sql_top5_ip)
    print("\nTop 5 请求路径（按请求次数降序）:\n")
    show_SQL_result(sql_top5_request)
    print("\nHTTP状态码分布（各状态码的请求数及占比）:\n")
    show_SQL_result(sql_httpcode_status)
    print("\n每小时请求量趋势（仅展示有数据的时段）:\n")
    show_SQL_result(sql_everyhour_questcount)
    print("\n异常高频 IP（单 IP > 2次/小时）:\n")
    show_SQL_result(sql_high_freq_ips)
    if args.output is None:
        pass
    else:
        export_CSV(query_db(c, sql_top5_ip), args.output)
        export_CSV(query_db(c, sql_top5_request), args.output)
        export_CSV(query_db(c, sql_httpcode_status), args.output)
        export_CSV(query_db(c, sql_everyhour_questcount), args.output)
        export_CSV(query_db(c, sql_high_freq_ips), args.output)
    close_db(c)
    pass
