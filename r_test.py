import sys
from huawei_3g import modem


print(str(sys.argv))
if len(sys.argv) != 3:
    print("Use: r_test.py Number Message")
else:
    modems=modem.load()
    modems[0].send_sms(sys.argv[1],sys.argv[2])
