
## 原项目 Invoke-Portscan:
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Invoke-Portscan.ps1
 ```
 Invoke-PortscanPro -Hosts  10.10.10.2  -ports {8088,80,6379} -threads 5

Hostname      : 10.10.10.2
alive         : True
openPorts     : {6379, 80}
closedPorts   : {8088}
filteredPorts : {}
finishTime    : 2019-07-26 17:28:28
 ```

## Invoke-PortscanPro:

在内网探测过程中我们经常要使用到端口信息探测,使用代理扫描会存在丢包现象,上传到被控机可能被杀软识.此项目就是为了解决这种问题,powershell结合cobaltstrike完美实现无文件落地,在原项目Invoke-Portscan基础上添加了如下功能:
* 端口服务识别和
* 获取web title

### example:
* 添加 -sports 识别端口
* 添加 -sports {8080,8022} 识别8080,8022端口
* 添加 -sports * 识别所有开放端口
```
Invoke-PortscanPro -Hosts  10.10.10.2  -ports {8088,80,6379} -threads 5 -sports {6379}

Hostname      : 10.10.10.2
alive         : True
openPorts     : {6379, 80}
closedPorts   : {8088}
filteredPorts : {}
finishTime    : 2019-07-26 17:28:28
port          : service
6379          : redis

Invoke-PortscanPro -Hosts  10.10.10.2  -ports {8088,80,6379} -threads 5 -sports *

Hostname      : 10.10.10.2
alive         : True
openPorts     : {6379, 80}
closedPorts   : {8088}
filteredPorts : {}
finishTime    : 2019-07-26 17:28:28
port          : service
6379          : redis
80            : status:Forbidden;title:None;


Invoke-PortscanPro -Hosts  10.10.10.2/24  -TopPorts 50 -threads 20 -sports {80,8080,8888}

```
