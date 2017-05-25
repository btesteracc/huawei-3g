import netifaces
from huawei_3g import modem

interface=modem.find()[0].get('interface')
gws=netifaces.gateways()
for nettpl in gws[netifaces.AF_INET]:
	if nettpl[1]==interface:
		ip=nettpl[0]
		break
print(ip)
	
