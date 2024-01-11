import requests
import json
import sys
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

config_file = open("config.json", "r")
config_data = json.load(config_file)

#============================================================================================
# display APs under the WLC
#============================================================================================
def get_ap_list():
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    ap_oper = config_data["ap_oper"]

    url = base_url + ap_oper + "/ap-name-mac-map"

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))

#    print(response.text)
    return json.loads(response.text)

#============================================================================================
# display WLANs under the WLC
#============================================================================================
def get_wlan_list():
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    wlan_config = config_data["wlan_config"]

    url =  base_url + wlan_config + "/wlan-cfg-entries/wlan-cfg-entry"

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))

#    print(response.text)
    return json.loads(response.text)

#============================================================================================
# display AP radio operation info from "Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"
#============================================================================================
def get_ap_radio_oper_info(wtp_mac, radio_slot_id):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    ap_oper = config_data["ap_oper"]

    url = base_url + ap_oper + "/radio-oper-data=" + wtp_mac + "," + str(radio_slot_id)

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    try:
        response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error : ",e)
    else:
#        print(response.text)
        return json.loads(response.text)

#============================================================================================
# display AP operation info from "Cisco-IOS-XE-wireless-access-point-oper:oper-data"
#============================================================================================
def get_ap_oper_info(wtp_mac):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    ap_oper = config_data["ap_oper"]

    url = base_url + ap_oper + "/oper-data=" + wtp_mac

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    try:
        response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error : ",e)
    else:
#        print(response.text)
        return json.loads(response.text)

#============================================================================================
# display AP MAC address from "Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map"
#============================================================================================
def get_wtp_mac_by_ap_name(ap_name):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    ap_oper = config_data["ap_oper"]

    ap_mac = "nomac"
    ap_list = get_ap_list()

    for aplist in ap_list["Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map"]:
        if ap_name == aplist["wtp-name"]:
            ap_mac = aplist["wtp-mac"]
    if ap_mac != "nomac":
    #    print(ap_mac)
        return ap_mac
    else:
        print("Input correct AP name")
        sys.exit()

#============================================================================================
# display WLAN ID from "Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-entry"
#============================================================================================
def get_wlan_id_by_wlan_profile_name(wlan_profile_name):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    wlan_config = config_data["wlan_config"]

    wlan_id = ""
    wlan_list = get_wlan_list()

    for wlanlist in wlan_list["Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-entry"]:
        if wlan_profile_name == wlanlist["profile-name"]:
            wlan_id = wlanlist["wlan-id"]

#    print(wlan_id)
    return wlan_id

#============================================================================================
# display ssid counters info from "Cisco-IOS-XE-wireless-access-point-oper:ssid-counters"
#============================================================================================
def get_ssid_counters(wtp_mac, radio_slot_id, wlan_id):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    ap_oper = config_data["ap_oper"]

    url = base_url + ap_oper + "/ssid-counters=" + wtp_mac + "," + str(radio_slot_id) + "," + str(wlan_id)

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    try:
        response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error : ",e)
    else:
#        print(response.text)
        return json.loads(response.text)

#============================================================================================
# display CAPWAP info from "Cisco-IOS-XE-wireless-access-point-oper:capwap-data"
#============================================================================================
def get_capwap_data(wtp_mac):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    ap_oper = config_data["ap_oper"]

    url = base_url + ap_oper + "/capwap-data=" + wtp_mac

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    try:
        response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error : ",e)
    else:
#        print(response.text)
        return json.loads(response.text)

#============================================================================================
# display RRM operation info from "Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data"
#============================================================================================
def get_rrm_oper_info(wtp_mac, radio_slot_id):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    rrm_oper = config_data["rrm_oper"]

    url = base_url + rrm_oper + "/rrm-measurement=" + wtp_mac + "," + str(radio_slot_id)

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    try:
        response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error : ",e)
    else:
#        print(response.text)
        return json.loads(response.text)

#============================================================================================
# dispaly AP summary info from many sources with AP name and radio slot number
#============================================================================================
def get_ap_info_by_ap_name_slot_id(ap_name, radio_slot_id):
    wtp_mac = get_wtp_mac_by_ap_name(ap_name)
    ap_capwap_data = get_capwap_data(wtp_mac)
    ap_oper_info = get_ap_oper_info(wtp_mac)
    ap_radio_oper_info = get_ap_radio_oper_info(wtp_mac, radio_slot_id)
    ap_rrm_oper_info = get_rrm_oper_info(wtp_mac, radio_slot_id)

    ap_channel = ap_radio_oper_info["Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"][0]["phy-ht-cfg"]["cfg-data"]["curr-freq"]
    ap_channel_util = ap_rrm_oper_info["Cisco-IOS-XE-wireless-rrm-oper:rrm-measurement"][0]["load"]["cca-util-percentage"]
    ap_station_num = ap_rrm_oper_info["Cisco-IOS-XE-wireless-rrm-oper:rrm-measurement"][0]["load"]["stations"]
    ap_tpc = ap_radio_oper_info["Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"][0]["radio-band-info"][0]["phy-tx-pwr-cfg"]["cfg-data"]["current-tx-power-level"]
    ap_wlan_list = ap_radio_oper_info["Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"][0]["vap-oper-config"]

    ### configuration settting information
    ap_ipaddress = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-ip-addr"]
    ap_netmask = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-ip-netmask"]
    ap_gateway = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-ip-gateway"]
    ap_nameserver = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-name-server"]
    ap_prime_wlc = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-prime-info"]["primary-controller-ip-addr"]
    ap_second_wlc = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-prime-info"]["secondary-controller-ip-addr"]
    ap_tertiary_wlc = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-prime-info"]["tertiary-controller-ip-addr"]
    ap_serial = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["device-detail"]["static-info"]["board-data"]["wtp-serial-num"]
    ap_model = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["device-detail"]["static-info"]["ap-models"]["model"]
    ap_sw_ver = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["device-detail"]["wtp-version"]["sw-version"]
    ap_policy_tag = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["tag-info"]["resolved-tag-info"]["resolved-policy-tag"]
    ap_site_tag = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["tag-info"]["resolved-tag-info"]["resolved-site-tag"]
    ap_rf_tag = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["tag-info"]["resolved-tag-info"]["resolved-rf-tag"]



#    print(ap_wlan_list)

    mylist = []
    mydict = {}
    for wlist in ap_wlan_list:
        mydict['wlan-id'] = wlist['wlan-id']
        mydict['wlan-profile-name'] = wlist['wlan-profile-name']
        mydict['ssid'] = wlist['ssid']
        mylist.append(mydict.copy())

#    print(mylist)

    dict_value = {
        "ap_name": ap_name,
        "ap_mac": wtp_mac,
        "ap_ipaddress": ap_ipaddress,
        "ap_netmask": ap_netmask,
        "ap_gateway": ap_gateway,
        "ap_nameserver": ap_nameserver,
        "ap_prime_wlc": ap_prime_wlc,
        "ap_second_wlc": ap_second_wlc,
        "ap_tertiary_wlc": ap_tertiary_wlc,
        "ap_serial": ap_serial,
        "ap_model": ap_model,
        "ap_sw_ver": ap_sw_ver,
        "ap_policy_tag": ap_policy_tag,
        "ap_site_tag": ap_site_tag,
        "ap_rf_tag": ap_rf_tag,
        "slot_id": radio_slot_id,
        "ap_channel": ap_channel,
        "ap_channel_util": ap_channel_util,
        "ap_station_num": ap_station_num,
        "ap_tpc": ap_tpc
    }
    dict_value['ssids'] = mylist

#    print(json.dumps(dict_value, indent=2))
    return dict_value

#============================================================================================
# dispaly AP summary info from many sources with AP name ONLY
#============================================================================================
def get_ap_info_by_ap_name(ap_name):
    wtp_mac = get_wtp_mac_by_ap_name(ap_name)
    ap_capwap_data = get_capwap_data(wtp_mac)
    ap_oper_info = get_ap_oper_info(wtp_mac)

    ap_slot_num = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["num-radio-slots"]

    slot_list = []
    slot_dict = {}

    for slot_id in range(ap_slot_num):
        ap_radio_oper_info = get_ap_radio_oper_info(wtp_mac, slot_id)
        ap_rrm_oper_info = get_rrm_oper_info(wtp_mac, slot_id)

        ap_channel = ap_radio_oper_info["Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"][0]["phy-ht-cfg"]["cfg-data"]["curr-freq"]
        ap_channel_util = ap_rrm_oper_info["Cisco-IOS-XE-wireless-rrm-oper:rrm-measurement"][0]["load"]["cca-util-percentage"]
        ap_station_num = ap_rrm_oper_info["Cisco-IOS-XE-wireless-rrm-oper:rrm-measurement"][0]["load"]["stations"]
        ap_tpc = ap_radio_oper_info["Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"][0]["radio-band-info"][0]["phy-tx-pwr-cfg"]["cfg-data"]["current-tx-power-level"]
        ap_wlan_list = ap_radio_oper_info["Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"][0]["vap-oper-config"]

        slot_dict['slot_id'] = str(slot_id)
        slot_dict['ap_channel'] = str(ap_channel)
        slot_dict['ap_channel_util'] = str(ap_channel_util)
        slot_dict['ap_station_num'] = str(ap_station_num)
        slot_dict['ap_tpc'] = str(ap_tpc)

        ssid_list = []
        ssid_dict = {}

        for wlist in ap_wlan_list:
            ssid_dict['wlan_id'] = wlist['wlan-id']
            ssid_dict['wlan_profile_name'] = wlist['wlan-profile-name']
            ssid_dict['ssid'] = wlist['ssid']
            ssid_list.append(ssid_dict.copy())

        slot_dict["ssids"] = ssid_list
        slot_list.append(slot_dict.copy())

    ### configuration settting information
    ap_ipaddress = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-ip-addr"]
    ap_netmask = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-ip-netmask"]
    ap_gateway = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-ip-gateway"]
    ap_nameserver = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-ip-data"]["ap-name-server"]
    ap_prime_wlc = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-prime-info"]["primary-controller-ip-addr"]
    ap_second_wlc = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-prime-info"]["secondary-controller-ip-addr"]
    ap_tertiary_wlc = ap_oper_info["Cisco-IOS-XE-wireless-access-point-oper:oper-data"][0]["ap-prime-info"]["tertiary-controller-ip-addr"]
    ap_serial = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["device-detail"]["static-info"]["board-data"]["wtp-serial-num"]
    ap_model = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["device-detail"]["static-info"]["ap-models"]["model"]
    ap_sw_ver = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["device-detail"]["wtp-version"]["sw-version"]
    ap_policy_tag = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["tag-info"]["resolved-tag-info"]["resolved-policy-tag"]
    ap_site_tag = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["tag-info"]["resolved-tag-info"]["resolved-site-tag"]
    ap_rf_tag = ap_capwap_data["Cisco-IOS-XE-wireless-access-point-oper:capwap-data"][0]["tag-info"]["resolved-tag-info"]["resolved-rf-tag"]

    dict_value = {
        "ap_name": ap_name,
        "ap_mac": wtp_mac,
        "ap_ipaddress": ap_ipaddress,
        "ap_netmask": ap_netmask,
        "ap_gateway": ap_gateway,
        "ap_nameserver": ap_nameserver,
        "ap_prime_wlc": ap_prime_wlc,
        "ap_second_wlc": ap_second_wlc,
        "ap_tertiary_wlc": ap_tertiary_wlc,
        "ap_serial": ap_serial,
        "ap_model": ap_model,
        "ap_sw_ver": ap_sw_ver,
        "ap_policy_tag": ap_policy_tag,
        "ap_site_tag": ap_site_tag,
        "ap_rf_tag": ap_rf_tag
    }
    dict_value["slots"] = slot_list


#    print(json.dumps(dict_value, indent=2))
    return dict_value
