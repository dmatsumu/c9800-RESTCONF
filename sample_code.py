import json
import getApInfo04 as AP
import getClientInfo05 as CL

print("### Fail pattern AP summary info by AP name and slot Id  ###")
ap_info = AP.get_ap_info_by_ap_name_slot_id("CCCC9120AXI",0)
print(json.dumps(ap_info, indent=2))

print("### Fail pattern AP summary info  ###")
ap_info = AP.get_ap_info_by_ap_name("CCCC9120AXI")
print(json.dumps(ap_info, indent=2))

print("### AP summary info  ###")
ap_info = AP.get_ap_info_by_ap_name("C9120AXI")
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
client_summary_info_ip = CL.get_client_summary_by_ip("10.10.30.242")
print(json.dumps(client_summary_info_ip, indent=2))

print("### Fail pattern client summary info by ip ###")
client_summary_info_ip = CL.get_client_summary_by_ip("1.1.3.242")
print(json.dumps(client_summary_info_ip, indent=2))

print("### client summary info by username ###")
client_summary_info_username = CL.get_client_summary_by_username("bonita")
print(json.dumps(client_summary_info_username, indent=2))


print("### Fail pattern client summary info by username ###")
client_summary_info_username = CL.get_client_summary_by_username("Purin")
print(json.dumps(client_summary_info_username, indent=2))
