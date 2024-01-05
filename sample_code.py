import json
import getApInfo02 as AP

ap_info = AP.get_ap_info_by_ap_name("<AP Name>")
print(json.dumps(ap_info, indent=2))

print("### wlan info ###")
winfo = AP.get_wlan_list()
print(json.dumps(winfo, indent=2))

print("### wlan id ###")
wlanid = AP.get_wlan_id_by_wlan_profile_name("<WLAN(SSID) Profile Name>")
print(wlanid)

