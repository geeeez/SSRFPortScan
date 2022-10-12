## SSRFPortScan

最近在做ssrf的一些漏洞利用的时候发现ssrfmap和一些现有的扫描内网端口的工具都不够灵活，所以写了一个简单的利用ssrf扫描内网端口的工具。

这个工具主要是为了进行ssrf探测内网端口使用的，他可以指定不同的协议，不同的ip，不同的端口扫描。可根据指定的字段来判断这个端口是否开放，可以指定ssl，并且支持自动生成一些ip段和端口段。

主要使用场景是通过burp抓到的数据包直接用$ssrf$标记ssrf位置，脚本会自动替换为payload，并根据响应来探测端口是否存活。总体来说就是比较灵活。

## 安装

目前仅支持python3

```bash
git clone https://github.com/geeeez/SSRFPortScan.git

cd SSRFPortScan

pip install -r requirement.txt

python3 SSRF_port_scan.py
```

## 使用

### 基础使用

判断123.txt数据包中存在ssrf的攻击的内网172.21.0.0-172.21.0.255 网段是否存在6379开放的ip，指定规则：如果响应中存在could not connect为不开放。

```bash
python3 SSRF_port_scan.py -ip 172.21.0.0/24 -port 6379 -reg_words "could not connect" -is_open 0 -threads 20 -r 123.txt
```

### 说明文档

|  参数 | 功能 |
|  ----  | ----  |
| -ip | 必需｜指定ip 可以是单个ip 也可以是ip段 比如172.20.0.0/24（使用的IPy库）目前也不是太灵活 |
| -port | 必需｜扫描指定port，如果是all就是所有port，可以是单个port 或者是8000-9000，或者是80，8080 |
| -r | 必需｜指定数据包，一般为burp中直接copy出来的数据包（$ssrf$指定payload替换位置） |
| -reg_words | 必需｜查找response中的指定字符，结合-is_open用来灵活判断扫描端口是否开放 |
| -protocol | 非必需｜指定协议，默认是http |
| -is_open | 非必需｜在响应中查找到上面的参数reg_words时判断为open还是close？1是open 0是close。 |
| -timeout | 非必需｜指定响应超时时间，目前暂未实现，后续会实现。可用在加快扫描速度。 |
| -threads | 非必需｜指定线程，默认为10 |
| -ssl | 非必需｜指定-r数据包的请求是http的还是https，默认为http |
