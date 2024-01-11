import requests
import json
import sys
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

config_file = open("config.json", "r")
config_data = json.load(config_file)

#============================================================================================
# display Client common operation data under the WLC
#============================================================================================
def get_common_oper_data():
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/common-oper-data"

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))

#    print(response.text)
    return json.loads(response.text)

#============================================================================================
# display Client dot11 operation data under the WLC
#============================================================================================
def get_dot11_oper_data():
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/dot11-oper-data"

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))

#    print(response.text)
    return json.loads(response.text)

#============================================================================================
# display Client traffic stastics under the WLC
#============================================================================================
def get_traffic_stats():
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/traffic-stats"

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))

#    print(response.text)
    return json.loads(response.text)

#============================================================================================
# display Client ip mac binding table under the WLC
#============================================================================================
def get_sisf_db_mac():
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/sisf-db-mac"

    payload={}
    headers={
        "Accept" : "application/yang-data+json"
    }

    response = requests.get(url, headers=headers, data=payload, verify=False, auth=HTTPBasicAuth(user, password))

#    print(response.text)
    return json.loads(response.text)


#============================================================================================
# display Client common operation data by mac under the WLC
#============================================================================================
def get_common_oper_data_by_mac(client_mac):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/common-oper-data=" + client_mac

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
# display Client dot11 operation data by mac under the WLC
#============================================================================================
def get_dot11_oper_data_by_mac(client_mac):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/dot11-oper-data=" + client_mac

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
# display Client traffic stastics by mac under the WLC
#============================================================================================
def get_traffic_stats_by_mac(client_mac):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/traffic-stats=" + client_mac

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
# display Client ip mac binding table by mac under the WLC
#============================================================================================
def get_sisf_db_mac_by_mac(client_mac):
    user = config_data["user"]
    password = config_data["password"]
    base_url = config_data["base_url"]
    client_oper = config_data["client_oper"]

    url = base_url + client_oper + "/sisf-db-mac=" + client_mac

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
# display Client IP address by mac
#============================================================================================
def get_client_ip_by_mac(client_mac):
    ip_address = "noip"
    ip_list = get_sisf_db_mac_by_mac(client_mac)

    ip_address = ip_list["Cisco-IOS-XE-wireless-client-oper:sisf-db-mac"][0]["ipv4-binding"]["ip-key"]["ip-addr"]

    if ip_address != "noip":
#        print(ip_address)
        return ip_address
    else:
        print("there is no ip address by mac you input")
        sys.exit()

#============================================================================================
# display Client MAC address by Client IP
#============================================================================================
def get_client_mac_by_ip(ip_address):

    client_mac = "nomac"
    client_list = get_sisf_db_mac()

    for clientlist in client_list["Cisco-IOS-XE-wireless-client-oper:sisf-db-mac"]:
        if ip_address == clientlist["ipv4-binding"]["ip-key"]["ip-addr"]:
            client_mac = clientlist["mac-addr"]

    if client_mac != "nomac":
#        print(client_mac)
        return client_mac
    else:
        print("Input correct IP address")
        sys.exit()

#============================================================================================
# display Client MAC address by username
#============================================================================================
def get_client_mac_by_username(username):

    client_mac = "nomac"
    client_list = get_common_oper_data()

    mylist = []
    mydict = {}
    for clientlist in client_list["Cisco-IOS-XE-wireless-client-oper:common-oper-data"]:
        if "username" in clientlist:
            if username == clientlist["username"]:
                client_mac = clientlist["client-mac"]
                mydict['client_mac'] = client_mac
                mylist.append(mydict.copy())
    if client_mac != "nomac":
#        print(mylist)
        return mylist
    else:
        print("There is no username you input")
        sys.exit()

#============================================================================================
# dispaly Client info summary by Client IP
#============================================================================================
def get_client_summary_by_ip(ip_address):

    client_mac = get_client_mac_by_ip(ip_address)
    client_common_oper_data = get_common_oper_data_by_mac(client_mac)
    client_dot11_oper_data = get_dot11_oper_data_by_mac(client_mac)
    client_traffic_stats = get_traffic_stats_by_mac(client_mac)

    ### common operation data
    client_connect_ap = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["ap-name"]
    client_connect_slot = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["ms-ap-slot-id"]
    if "username" in client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]:
        client_username = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["username"]
    else:
        client_username = ""
    client_method = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["method-id"]

    ### dot11 operation data
    client_dot11_state = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["dot11-state"]
    client_connect_channel = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["current-channel"]
    client_connect_ssid = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["vap-ssid"]
    client_connect_wlan_profile = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["wlan-profile"]

    ### traffic stastics
    client_bytes_rx = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["bytes-rx"]
    client_bytes_tx = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["bytes-tx"]
    client_rssi = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["most-recent-rssi"]
    client_snr = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["most-recent-snr"]
    client_spatial_stream = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["spatial-stream"]

    dict_value = {}
    dict_value = {
        "client_ip": ip_address,
        "client_mac": client_mac,
        "client_connect_ap": client_connect_ap,
        "client_connect_slot": client_connect_slot,
        "client_username": client_username,
        "client_method": client_method,
        "client_dot11_state": client_dot11_state,
        "client_connect_channel": client_connect_channel,
        "client_connect_ssid": client_connect_ssid,
        "client_connect_wlan_profile": client_connect_wlan_profile,
        "client_bytes_rx": client_bytes_rx,
        "client_bytes_tx": client_bytes_tx,
        "client_rssi": client_rssi,
        "client_snr": client_snr,
        "client_spatial_stream": client_spatial_stream
    }

#    print(dict_value)
    return dict_value

#============================================================================================
# dispaly Client info summary by Client username
#============================================================================================
def get_client_summary_by_username(username):

    client_mac_list = get_client_mac_by_username(username)

    list_value = []
    for clientmac in client_mac_list:
        client_mac = clientmac["client_mac"]
        client_common_oper_data = get_common_oper_data_by_mac(client_mac)
        client_dot11_oper_data = get_dot11_oper_data_by_mac(client_mac)
        client_traffic_stats = get_traffic_stats_by_mac(client_mac)
        ip_address = get_client_ip_by_mac(client_mac)

        ### common operation data
        client_connect_ap = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["ap-name"]
        client_connect_slot = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["ms-ap-slot-id"]
        if "username" in client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]:
            client_username = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["username"]
        else:
            client_username = ""
        client_method = client_common_oper_data["Cisco-IOS-XE-wireless-client-oper:common-oper-data"][0]["method-id"]

        ### dot11 operation data
        client_dot11_state = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["dot11-state"]
        client_connect_channel = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["current-channel"]
        client_connect_ssid = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["vap-ssid"]
        client_connect_wlan_profile = client_dot11_oper_data["Cisco-IOS-XE-wireless-client-oper:dot11-oper-data"][0]["wlan-profile"]

        ### traffic stastics
        client_bytes_rx = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["bytes-rx"]
        client_bytes_tx = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["bytes-tx"]
        client_rssi = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["most-recent-rssi"]
        client_snr = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["most-recent-snr"]
        client_spatial_stream = client_traffic_stats["Cisco-IOS-XE-wireless-client-oper:traffic-stats"][0]["spatial-stream"]

        dict_value = {}
        dict_value = {
            "client_ip": ip_address,
            "client_mac": client_mac,
            "client_connect_ap": client_connect_ap,
            "client_connect_slot": client_connect_slot,
            "client_username": client_username,
            "client_method": client_method,
            "client_dot11_state": client_dot11_state,
            "client_connect_channel": client_connect_channel,
            "client_connect_ssid": client_connect_ssid,
            "client_connect_wlan_profile": client_connect_wlan_profile,
            "client_bytes_rx": client_bytes_rx,
            "client_bytes_tx": client_bytes_tx,
            "client_rssi": client_rssi,
            "client_snr": client_snr,
            "client_spatial_stream": client_spatial_stream
        }
        list_value.append(dict_value.copy())
#        printlist_value)
        # this function returns list format because one user may have several devices.
        return list_value
