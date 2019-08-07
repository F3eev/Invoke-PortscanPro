
## Invoke-PortscanPro:

在内网探测过程中我们经常要使用到端口信息探测,使用代理扫描会存在丢包现象,上传到被控机可能被杀软识.此项目就是为了解决这种问题,powershell结合cobaltstrike完美实现无文件落地,在原项目[Invoke-Portscan](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Invoke-Portscan.ps1)基础上添加了如下功能:
* 端口服务识别和
* 获取web title

### example:
* 添加 -sports 识别端口
* 添加 -sports {8080,8022} 识别8080,8022端口
* 添加 -sports * 识别所有开放端口
* 自动获取主机netbios信息
```
Invoke-PortscanPro -Hosts 127.0.0.1  -ports {3306,445,1433,135,3389} -threads 5 -sports *

Hostname          : 127.0.0.1
alive             : True
openPorts         : {3306, 445, 135, 3389}
closedPorts       : {1433}
filteredPorts     : {}
finishTime        : 2019-08-07 22:11:16
os                : Windows 7 Professional 7601 Service Pack 1Windows 7 Professional 6.1
DNS computer name : PC-WIN.test.com
DNS tree name     : test.com
DNS domain name   : test.com
Computer name     : PC-WIN
Domain name       : TEST
135               : netbios
3389              : msrdp
3306              : mysql
445               : smb


```
