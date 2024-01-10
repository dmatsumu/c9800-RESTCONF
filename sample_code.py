import json
import getApInfo02 as AP
import getClientInfo01 as CL

ap_info = AP.get_ap_info_by_ap_name("AP9136")
print(json.dumps(ap_info, indent=2))

print("### wlan info ###")
winfo = AP.get_wlan_list()
print(json.dumps(winfo, indent=2))

print("### wlan id ###")
wlanid = AP.get_wlan_id_by_wlan_profile_name("KTEST3")
print(wlanid)

print("### client common operation data ###")
client_common_oper_data = CL.get_common_oper_data()
print(json.dumps(client_common_oper_data, indent=2))

print("### client summary info by ip ###")
client_summary_info = CL.get_client_summary_by_ip("10.10.30.242")
print(json.dumps(client_summary_info, indent=2))
