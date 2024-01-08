# c9800-RESTCONF

## Abstract

C9800 can be accessed from RESTCONF using YANG model. But YANG model is very difficult to find the correct url and parameters. So I created the C9800 API wrapper. This is useful for the c9800 API beginner because you don't have to care about IOS-XE YANG model.

## Installation 
### Clone the repo

```
git clone https://github.com/dmatsumu/c9800-RESTCONF
```

### Go to your project folder

```
cd c9800-RESTCONF
```

### install virtualenv via pip

```
pip install virtualenv
```

### Create the venv

```
python3 -m venv .
```

### Activte your venv

```
source ./bin/activate
```

## Usage
### Setup config.json
You need to input parameter into "config.json" file according to your environment.

### import getApInfo.py to your code
You need to import "getApInfo.py" into your python code. Reffering to the sample_code.py, if you need a detail.

## Function list

### def get_ap_list():
display APs under the WLC

### def get_wlan_list():
display WLANs under the WLC

### def get_ap_radio_oper_info(wtp_mac, radio_slot_id):
display AP radio operation info from "Cisco-IOS-XE-wireless-access-point-oper:radio-oper-data"

### def get_ap_oper_info(wtp_mac):
display AP operation info from "Cisco-IOS-XE-wireless-access-point-oper:oper-data"

### def get_wtp_mac_by_ap_name(ap_name):
display AP MAC address from "Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map"

### def get_wlan_id_by_wlan_profile_name(wlan_profile_name):
display WLAN ID from "Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-entry"

### def get_ssid_counters(wtp_mac, radio_slot_id, wlan_id):
display ssid counters info from "Cisco-IOS-XE-wireless-access-point-oper:ssid-counters"

### def get_capwap_data(wtp_mac):
display CAPWAP info from "Cisco-IOS-XE-wireless-access-point-oper:capwap-data"

### def get_rrm_oper_info(wtp_mac, radio_slot_id):
display RRM operation info from "Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data"

### def get_ap_info_by_ap_name_slot_id(ap_name, radio_slot_id):
dispaly AP summary info from many sources with AP name and radio slot number

### def get_ap_info_by_ap_name(ap_name):
dispaly AP summary info from many sources with AP name ONLY

## Notes
- This python code is build in my lab environment. Please note that errors may occur depending on the environment.
- Client information will be created soon(maybe).
