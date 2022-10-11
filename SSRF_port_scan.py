import threading
import socket
import requests
import HackRequests
import argparse
from IPy import IP

hack = HackRequests.hackRequests()
white_protocol=["dict","http","https","smtp","telnet","ssh2","ogg","expect","ldap","php","zlib","zip","bzip","gopher","tftp","file","ftp","imap","pop3","rtsp","smb"]

# 需要解决的问题
# 1、超时问题
# 2、https的问题
# 3、显示问题


def is_white_protocol(protocol):
    if protocol in white_protocol:
        return True
    else:
        return False

# ip 内网要扫描的ip port内网要扫描的端口 reg_words 要判定为开放的关键字 protocol 扫描端口使用的协议 requests_type 请求的类型(比如是get还是post)
# timeout 超时事件，在一些内网扫描中 不存在的ip可能会是很耗时的存在，如果可以确定存在的ip的响应时间低于2s，那我们就可以设置超时为2s 加快速度。

def ssrf_port_scan(http_raw,ip,port,reg_words,protocol,timeout,is_open,ssl):
    with sem:
        http_raw = create_requests(http_raw,ip,port,protocol)
        requests_and_judge(ip,port,http_raw,reg_words,timeout,is_open,ssl)

def requests_and_judge(ip,port,http_raw,reg_words,timeout,is_open,ssl):
    hack = HackRequests.hackRequests()
    # print(http_raw)
    # print(reg_words)
    try:
        response = hack.httpraw(http_raw,proxy=('127.0.0.1','8082'),ssl=ssl)
        if is_open:
            if reg_words in response.text():
                print(str(ip) + "的端口" + str(port) + " is open\n")
        else:
            if reg_words not in response.text():
                print(str(ip) + "的端口" + str(port) + " is open\n")
    except:
        pass



def create_requests(http_raw,ip,port,protocol):
    whole_url = protocol+"://"+str(ip)+":"+str(port)
    final_http_raw =  http_raw.replace("$ssrf$",whole_url).replace("Content-Length","auth_test") #处理post的Content-Length不匹配问题
    return final_http_raw

def read_http_raw(path):
    with open(path,"r") as f:
        return f.read()

def parse_continuation_args(args_str):
    result_ports_list = list()
    if args_str == "all":
        return create_continuation_nums("1-65535")
    elif "-" in args_str:
        try:
            return create_continuation_nums(args_str)
        except:
            print("port参数格式无法被解析")
    elif "," in args_str:
        try:
            return args_str.split(",")
        except:
            print("port参数格式无法被解析")
    else:
        result_ports_list.append(args_str)
        return result_ports_list

def parse_ip(args_str):
    try:
        ips = IP(args_str)
        return ips
    except:
        print("ip地址格式无法被解析")


def create_continuation_nums(args_str):
    result_list = []
    list_args = args_str.split("-")
    start_num = int(list_args[0])
    end_num = int(list_args[1])
    for num in range(start_num,end_num+1):
        result_list.append(num)
    return result_list

if __name__ == '__main__':
    parser = argparse.ArgumentParser("description='SSRF_PORT_SCAN'")
    parser.add_argument('-ip')
    parser.add_argument('-port')
    parser.add_argument('-protocol',default='http')
    parser.add_argument('-reg_words')
    parser.add_argument('-r')
    parser.add_argument('-timeout',default=3)
    parser.add_argument('-is_open',default=1)
    parser.add_argument('-threads', default=20)
    parser.add_argument('-ssl', default=False)
    namespace = parser.parse_args()
    ip = namespace.ip
    port = namespace.port
    protocol = namespace.protocol
    reg_words = namespace.reg_words
    http_raw_path = namespace.r
    timeout = namespace.timeout
    http_raw = read_http_raw(http_raw_path)
    ips = parse_ip(ip)
    ports = parse_continuation_args(port)
    is_open = namespace.is_open
    threads = namespace.threads
    ssl = namespace.ssl
    if ssl:
        ssl=True
    #
    #限制线程的最大数量
    sem = threading.Semaphore(int(threads))

    #设置超时 因为hackrequests暂未实现burp倒入的包设置timeout,这里先用socket.setdefaulttimeout全局搞一下吧
    socket.setdefaulttimeout(float(timeout))
    #遍历所有端口和ip进行扫描
    for ip in ips:
        for port in ports:
            # ssrf_port_scan(http_raw,ip,port,reg_words,protocol,timeout,is_open)
            # 开启多线程
            threading.Thread(target=ssrf_port_scan,args=(http_raw,ip,port,reg_words,protocol,timeout,is_open,ssl)).start()

    #多线程
    # print(read_http_raw("123.txt"))