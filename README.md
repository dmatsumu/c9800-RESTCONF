# c9800-RESTCONF

## Abstract

C9800 can be accessed from RESTCONF using YANG model. But YANG model is very difficult to find the correct url and parameters. So I created the C9800 API wrapper. This is useful for the c9800 API beginner.

## How to use

### Setup config.json
You need to input parameter according to your environment.

### import getApInfo.py to your code
Reffering to the sample_code.py

## Function list

### display APs under the WLC
def get_ap_list():

### display WLANs under the WLC
def get_wlan_list():

### display AP radio operation info from "Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"
def get_ap_radio_oper_info(wtp_mac, radio_slot_id):

### display AP operation info from "Cisco-IOS-XE-wireless-access-point-oper:oper-data"
def get_ap_oper_info(wtp_mac):

### display AP MAC address from "Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map"
def get_wtp_mac_by_ap_name(ap_name):

### display WLAN ID from "Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-entry"
def get_wlan_id_by_wlan_profile_name(wlan_profile_name):

### display ssid counters info from "Cisco-IOS-XE-wireless-access-point-oper:ssid-counters"
def get_ssid_counters(wtp_mac, radio_slot_id, wlan_id):

### display CAPWAP info from "Cisco-IOS-XE-wireless-access-point-oper:capwap-data"
def get_capwap_data(wtp_mac):

### display RRM operation info from "Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data"
def get_rrm_oper_info(wtp_mac, radio_slot_id):

### dispaly AP summary info from many sources with AP name and radio slot number
def get_ap_info_by_ap_name_slot_id(ap_name, radio_slot_id):

### dispaly AP summary info from many sources with AP name ONLY
def get_ap_info_by_ap_name(ap_name):

## Notes
- This python code is build in my lab environment. Please note that errors may occur depending on the environment.
- Client information will be created soon(maybe).
