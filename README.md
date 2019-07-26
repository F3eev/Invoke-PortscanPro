# Invoke-PortscanPro
## 原项目:
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Invoke-Portscan.ps1

## 保留原项目所有功能,在此项目上添加了端口服务识别功能代码,web服务可以获取title
```
Invoke-PortscanPro -Hosts  127.0.0.1  -ports {8088,80,6379} -threads 5 -sports {6379}

Hostname      : 127.0.0.1
alive         : True
openPorts     : {6379}
closedPorts   : {8088, 80}
filteredPorts : {}
finishTime    : 2019-07-26 17:28:28
port          : service
6379          : redis
```
