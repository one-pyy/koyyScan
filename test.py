from src.model.finger import Finger,Ip, Port, Protocal, Service, Version
from src.utils.data_format import finger_format,json_merge
from src.finger._nmap import finger_scan,devices_check
import json
if __name__ == "__main__":

    # service = Service("openssh", "None")
    # host1 = "1.1.1.1"
    # finger1 = [(22,'ipcam',Service("Hikvision IPCam control port", "")),(21,'ssh',Service("openssh", "5.1p1 Debian 5"))]
    # host2 = "2.2.2.2"
    # finger2 = [(22,'tcp','ssh/N'),(21,'tcp','ftp/2.2.2')]
    # host3 = "2.2.2.3"
    # finger3 = [(22,'tcp','ssh/N'),(21,'tcp','ftp/2.2.2')]
    # jsondata1 = finger_format(host1,finger1)
    # jsondata2 = finger_format(host2,finger2)
    # jsondata3 = finger_format(host3,finger3)
    # print(jsondata1)
    # data = {}
    # data.update(jsondata2)
    # print(data)

    # data1 = json.loads(jsondata1)
    # print(data1)
    # data2 = json.loads(jsondata2)
    # merged_data = json.dumps({**data1, **data2})
    # print(merged_data),
    # ans = finger_scan("211.22.90.152",[80,8000])
    ans=[]
    ans.append(finger_scan("206.189.61.150",[22,7777]))
    ans.append(finger_scan("211.22.90.145",[8099,8100]))
    print(ans)