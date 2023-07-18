pfsense:

    检查操作系统指纹中是否包含FreeBSD
    80端口标题包含pfSense字符串
    443端口SSL证书中包含pfSense
Hikvision:

    80端口标题包含Hikvision
    开放80,8000等端口
    使用nmap http-title脚本获取设备标题
dahua:

    80端口标题包含netDvrV3
    开放端口包含80, 8000, 37777等
    SSL证书包含DHCAMS
cisco:

    启用SNMP脚本,检查sysDescr是否包含Cisco
    23端口Telnet banner包含Cisco
    端口组合含有80, 443, 22等
synology:

    5000端口title包含Synology
    开放端口如80, 443, 5000
    HTTP头包含Server: Synology NAS

glastopf:

    主要开放端口为 80
    http标题包含 Sioux Falls
    返回固定的无效页面内容
    可以使用nmap http自定义脚本验证
    
    title = nm[host]['tcp'][80]['script']['http-title']
    if 'Sioux Falls' in title:
      print(f"{host} is Glastopf Web Honeypot")
Kippo:

```python
#开放端口 2222 ssh
#ssh版本识别为 SSH-2.0-OpenSSH_5.1p1 Debian-5
#登录后展现独特的假提示

if 2222 in nm[host]['tcp'] and 'SSH-2.0-OpenSSH_5.1p1 Debian-5' in nm[host]['tcp'][2222]['version']:
  print(f"{host} is Kippo SSH Honeypot")
```
HFish:

    开放端口为23 telnet
    telnet提示符包含HoneyPot
    登录时有特殊的假交互
    
    if 'tcp' in nm[host] and 23 in nm[host]['tcp']:
        banner = nm[host]['tcp'][23]['script']['banner']
        if 'Microsoft Windows [Version 5.1.2600]' in banner:
        	print(f'{host} is likely Hfish Honeypot')
所以对于蜜罐识别,主要是通过几点:

1. 检查独特的端口开放情况
2. 验证服务版本是否为伪造的假版本
3. 与服务进行交互,观察响应的差异点