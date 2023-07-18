def get_servises():
    '''返回service组件列表'''
    return {"Windows","java","iis","centos","node.js","nginx","ubuntu","express","micro_httpd","openssh","asp.net","openresty","openssl","php","grafana","wordpress","MicrosoftHTTPAPI","Weblogic","LiteSpeed","rabbitmq","elasticsearch","Jetty","apache","debian"}

def get_honeypots():
    '''返回honeypot列表'''
    return {"glastopf","Kippo","HFish"}

def get_devices():
    '''返回device列表'''
    return {"firewall":"pfsense","Webcam":"Hikvision","switch":["dahua","cisco"],"Nas":"synology"}

def get_protocols():
    '''返回protocol列表'''
    return {"ssh","http","https","rtsp","ftp","telnet","amqp","mongodb","redis","mysql"}