#!/usr/bin/env python
# coding:utf-8
# @Time    : 2026/10/23 10:39
# @Author  : yangshuai
# @Site    : 
# @File    : service_daemon.py
# @Software: PyCharm 
# @Comment :
"""
从配置文件（YAML/TOML）读取服务列表（含检查命令、重启命令、最大重试次数）。
每隔 N 秒执行健康检查，失败时自动重启并记录日志，连续失败超阈值则发送告警（模拟即可）。
"""

# 使用argparse解析执行脚本时的传参
import argparse
import concurrent.futures
import json
# 记录日志
import logging
from logging.handlers import RotatingFileHandler
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

# 解析yaml文件
import yaml
import toml

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
log_name = "service_daemon.log"

# 默认执行命令超时时间
exec_exceed_time = 5

# 自定义告警，目前选择使用ssh远程登录到用户终端，弹窗提示信息，使用notify-send
remote_ip = '192.168.231.3'
remote_username = 'ys'

# 设置终止事件
stop_event = threading.Event()


def handle_signal(signum, _frame):
    logger.error('收到退出信号：%s，程序准备退出' % signum)
    # 设置退出信号检查状态
    stop_event.set()


#
signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


# 传参解析函数
def parse_args():
    parser = argparse.ArgumentParser(
        prog="Services Daemon",
        description="从配置文件（YAML/TOML）读取服务列表（含检查命令、重启命令、最大重试次数）。"
                    "每隔 N 秒执行健康检查，失败时自动重启并记录日志，连续失败超阈值则发送告警（模拟即可）。",
        epilog="示例：service_daemon.py -f ./myservice.yml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-f", "--file",
        type=str,
        help="配置文件名"
    )

    parser.add_argument(
        "-s", "--second",
        type=int,
        help="健康检查时间"
    )

    parser.add_argument(
        "--dry_run",
        action="store_true",
        help="是否开启dry-run模式"
    )

    return parser.parse_args()


# 判断传入的文件是否为yaml文件
def is_yaml_file(path: str) -> bool:
    myfile = Path(path)
    # 判断传入的是否为文件
    if not myfile.is_file():
        logger.error(f"{path} is not a file!")
        return False

    try:
        with open(file=path, mode='r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip():
                logger.error(f"{path} is empty")
                return False
            try:
                yaml.safe_load(content)
            except yaml.YAMLError:
                logger.info(f"{path} is not yaml file!")
                return False
            try:
                # 判断传入的是否为json文件
                json.loads(content)
                logger.error(f"{path} is json file!")
            except json.JSONDecodeError:
                logger.info(f"{path} is yaml file!")
                return True
    except (PermissionError, OSError, ValueError, UnicodeDecodeError) as e:
        logger.info(f"{type(e).__name__}: {e}")
        return False


# 判断传入的文件是否为toml文件
def is_toml_file(path: str) -> bool:
    myfile = Path(path)
    # 判断传入的是否为文件
    if not myfile.is_file():
        logger.error(f"{path} is not a file!")
        return False
    # 判断传入的是否为json文件
    try:
        with open(file=path, mode='r', encoding='utf-8-sig') as f:
            content = f.read()
            if not content.strip():
                logger.error(f"{path} is empty")
                return False
            toml.loads(content)
            logger.info(f"{path} is toml file!")
            return True
    except (toml.TomlDecodeError, PermissionError, OSError, ValueError, UnicodeDecodeError) as e:
        logger.info(f"{type(e).__name__}: {e}")
        return False


def save_json(file_name: str, services: dict) -> bool:
    try:
        # state = {s['name']: {'retry_count': s['retry_count'],
        #                      'is_warned': s['is_warned'],
        #                      'last_check_time': s['last_check_time']}
        #          for s in services}
        with open(file_name, 'w') as f:
            json.dump(services, f)
            return True
    except (TypeError, PermissionError, OSError, json.JSONDecodeError, ValueError) as e:
        logger.error(f"{type(e).__name__}: {e}")
        return False


def load_json(file_name: str) -> dict:
    try:
        if Path(file_name).is_file():
            with open(file_name) as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"{type(e).__name__}: {e}")
    return {}


def send_warning(ip_addr: str, username: str, title: str, send_str: str) -> bool:
    remote_command = f'DISPLAY=:0 notify-send "{title}" "{send_str}"'
    try:
        result = subprocess.run(['ssh', f'{username}@{ip_addr}', remote_command], capture_output=True, timeout=10)
        if result.returncode == 0:
            logger.info(f'to {ip_addr} warning message send success')
            return True
        else:
            try:
                output = result.stderr.decode('gbk')
            except UnicodeDecodeError:
                output = result.stderr.decode('utf-8', errors="replace")
            logger.error("command:%s run error %s" % (remote_command, output))
            return False
    except Exception as e:
        logger.error(f"{type(e).__name__}: {e}")
        return False


def service_process(myservice: dict, state_dict: dict, exceed_time: int, dry_run: bool) -> dict:
    if stop_event.is_set():
        logger.error('service:%s receive exit signal' % myservice['name'])
        return myservice
    # dry-run 模式只打印要做的事，不实际做
    if dry_run:
        logger.warning("dry_run mode,will check service:%s running state(execute %s command),"
                       "if not running(return code<>200) ,then execute %s to restart,max retry count is:"
                       "%d,this service will every %d second to check" % (myservice['name'],
                                                                          myservice['check_command'],
                                                                          myservice['restart_command'],
                                                                          myservice['max_retries'],
                                                                          myservice['check_interval']))
        return state_dict

    # 判断当前时间与上次检查时间差（秒）是否大于指定的服务检查间隔时间
    last_check_time = state_dict['last_check_time']
    now_time = time.time()
    sec_diff = now_time - last_check_time
    if sec_diff < state_dict['check_interval']:
        logger.info('service:%s every check second is less than setting:%d,now is:%d ' % (myservice['name'],
                                                                                          state_dict['check_interval'],
                                                                                          sec_diff))

        return state_dict
    # 执行检查状态命令
    logger.info('begin check service:%s,check command:%s' % (myservice['name'], myservice['check_command']))

    result = subprocess.run(myservice['check_command'], shell=True, capture_output=True, timeout=exceed_time)
    # 将检查过的时间更新
    state_dict['last_check_time'] = now_time
    # 检查通过,将轮询的重启次数，告警标识，检查间隔时间重置
    if result.returncode == 0:
        logger.info('service:%s is running' % myservice['name'])
        state_dict['retry_count'] = 0
        state_dict['is_warned'] = False
        state_dict['check_interval'] = myservice['check_interval']
        return state_dict
    else:
        # 检查不通过，判断stderr的字符集（windows可能用的不是utf-8）
        try:
            output = result.stderr.decode('gbk')
        except UnicodeDecodeError:
            output = result.stderr.decode('utf-8', errors="replace")
        # 打印执行检查命令输出的错误信息
        logger.info('service:%s check failed: %s' % (myservice['name'], output))

        # 判断重启失败次数是否到临界值，超过则不进行重启
        if state_dict['retry_count'] > myservice['max_retries']:
            logger.info('service:%s restart times exceed,default:%d,now:%d' %
                        (myservice['name'], myservice['max_retries'], state_dict['retry_count']))
            # 判断是否发送过告警，发送过就不再发
            if state_dict['is_warned']:
                logger.warning("service:%s restart times exceed,already send warning,this time don't send " %
                               (myservice['name'],))
                return state_dict
            else:
                warning_title = '%s run error' % myservice['name']
                warning_message = 'service:%s restart times exceed,default:%d,now:%d' % \
                                  (myservice['name'], state_dict['retry_count'], myservice['max_retries'])
                send_warning(remote_ip, remote_username, warning_title, warning_message)
                state_dict['is_warned'] = True
                return state_dict

        # 开始执行重启命令
        logger.info('service:%s is not running,begin restart，command:%s' % (myservice['name'],
                                                                            myservice['restart_command']))
        result_retry = subprocess.run(myservice['restart_command'], shell=True,
                                      capture_output=True, timeout=exceed_time)
        # 重启命令执行成功，打印日志
        if result_retry.returncode == 0:
            logger.info('service:%s restart success' % myservice['name'])
            return state_dict
        else:
            # 依旧判断失败的重启命令错误日志编码
            try:
                output = result_retry.stderr.decode('gbk')
            except UnicodeDecodeError:
                output = result_retry.stderr.decode('utf-8', errors="replace")

            # 打印重启失败信息
            logger.info('service:%s restart failed: %s' % (myservice['name'], output))

            # 重启失败次数+1
            state_dict['retry_count'] += 1

            # 退避策略，每次重启失败后重启间隔+10秒，减少对故障服务的冲击

            # state_dict['check_interval'] += 10

            return state_dict


def main():
    # 定义输出日志格式
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')
    # 定义处理器，输出到文件
    # file_handler = logging.FileHandler(log_name, encoding='utf-8-sig')
    # 文件大于10MB自动写入下一个文件，总备份5份
    file_handler = RotatingFileHandler(log_name, maxBytes=1024 * 1024 * 10, backupCount=5, encoding='utf-8-sig')
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.INFO)

    # 定义处理器，输出到控制台
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(logging.INFO)

    # 将两个处理器添加到记录器中
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    # 解析传入的参数
    args = parse_args()

    # 自定义json文件名称
    json_file_name = 'service_daemon_state.json'

    # 配置循环检测时间
    sleep_time = 5 if args.second is None else args.second
    # 配置配置文件
    configfile = "services.yml" if args.file is None else args.file
    if is_toml_file(configfile):
        load_func = toml.load
    elif is_yaml_file(configfile):
        load_func = yaml.safe_load
    else:
        sys.exit(1)
    with open(file=configfile, mode='r', encoding='utf-8-sig') as f:
        ymldata = load_func(f)

    # 从json文件获取服务监控历史状态
    state_dict = load_json(json_file_name)
    # 如果返回为空，则初始化state_dict字典
    if len(state_dict) == 0:
        logger.info("init dict:state_dict")
        for i in ymldata['services']:
            name = i['name']
            tmp_dict = {'retry_count': 0, 'last_check_time': time.time(), 'is_warned': False,
                        'check_interval': i['check_interval']}
            state_dict[name] = tmp_dict

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(ymldata['services']))
    while not stop_event.is_set():
        logger.info("-" * 65)
        logger.info("begin every %d second check" % sleep_time)
        # 下面两行使用标准语法执行并发任务，按照并发任务完成的先后顺序获取结果（而非按照任务提交的先后顺序获取）
        futures = {executor.submit(
            service_process, myservice, state_dict[myservice['name']], exec_exceed_time, args.dry_run): myservice for
                   myservice in
                   ymldata['services']}
        try:
            for future in concurrent.futures.as_completed(futures):
                service = futures[future]
                try:
                    rel_dic = future.result()
                    state_dict[service['name']] = rel_dic
                except Exception as exc:
                    logger.error(f'generated an exception(type:{type(exc).__name__}): %s' % exc)
        except KeyboardInterrupt:
            stop_event.set()
        logger.info("-" * 65)
        # 为了捕获信号，使用event.wait等待事件
        stop_event.wait(sleep_time)
    save_json(json_file_name, state_dict)
    executor.shutdown(wait=True)


if __name__ == '__main__':
    main()
    exit(0)
