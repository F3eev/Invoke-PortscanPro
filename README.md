
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

## Invoke-PortscanPro 说明:
保留原项目所有功能,在此项目上添加了端口服务识别功能代码,
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

```

