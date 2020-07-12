### NmapTools

Go语言学习，第一个练手小工具，解析nmap扫描结果xml转换到xlsx、进行web服务探测、进行socket数据探测。

### 截图

![index](https://github.com/CTF-MissFeng/NmapTools/blob/master/img/1.png)


### 功能演示

#### 一、xml转换到xlsx

```bash
./nmapTools -f test.xml -o test
2020/07/12 17:51:59 [+]解析成功，共计10001条IP及14063条端口数据
2020/07/12 17:51:59 [+]导出解析结果成功，请查看test.xlsx文件
```

![index](https://github.com/CTF-MissFeng/NmapTools/blob/master/img/2.png)


#### 二、Web服务探测

```bash
./nmapTools -f test.xml -w
......
2020/07/12 18:03:21 [-]不是有效的web服务,errer:Get "https://202.173.15.148:80": http: server gave HTTP response to HTTPS client
2020/07/12 18:03:25 [-]不是有效的web服务,errer:Get "https://218.5.42.5:22": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
2020/07/12 18:03:28 [-]不是有效的web服务,errer:Get "https://47.93.148.247:22": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
2020/07/12 18:03:28 [+]http服务探测保存成功，请查看 test.xml_http探测结果.xlsx
```

![index](https://github.com/CTF-MissFeng/NmapTools/blob/master/img/3.png)

#### 三、Socket数据探测

> 使用指定的命令进行Socket连接发送，能发现一些未授权访问服务漏洞，如dubbo、Hadoop等。

```bash
./nmapTools -f test.xml -s -c 100
......
2020/07/12 10:12:05 [-] 27.148.193.123:80 获取数据失败 error:read tcp 192.168.0.102:56400->27.148.193.123:80: i/o timeout
2020/07/12 10:12:05 [-] 49.234.14.18:80 获取数据失败 error:read tcp 192.168.0.102:56401->49.234.14.18:80: i/o timeout
2020/07/12 10:12:05 [+]socket服务探测保存成功，请查看 test.xml_socket探测结果.xlsx
```

![index](https://github.com/CTF-MissFeng/NmapTools/blob/master/img/4.png)