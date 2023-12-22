'''
    Create an XDR new inbcident : bundle incident + sightings + relationship
    v202311213
'''
import requests
import json
from crayons import *
from datetime import datetime, timedelta
import time
import sys


item_list=[]
discover_method=["Agent Disclosure","Antivirus","Audit","Customer","External - Fraud Detection","Financial Audit","HIPS","IT Audit","Incident Response","Internal - Fraud Detection","Law Enforcement"]

categories=["Denial of Service","Exercise/Network Defense Testing","Improper Usage","Investigation","Malicious Code","Scans/Probes/Attempted Access","Unauthorized Access"]

def read_api_keys(service):   
    # read API credentials from an external file on this laptop ( API keys are not shared with the flask application )
    if service=="webex":
        with open('../keys/webex_keys.txt') as creds:
            text=creds.read()
            cles=text.split('\n')
            ACCESS_TOKEN=cles[0].split('=')[1].strip()
            ROOM_ID=cles[1].split('=')[1].strip()
            #print(ACCESS_TOKEN,ROOM_ID) 
            return(ACCESS_TOKEN,ROOM_ID)
    if service=="ctr":
        if ctr_client_id=='paste_CTR_client_ID_here':
            with open('../keys/ctr_api_keys.txt') as creds:
                text=creds.read()
                cles=text.split('\n')
                client_id=cles[0].split('=')[1]
                client_password=cles[1].split('=')[1]
                #access_token = get_token()
                #print(access_token) 
        else:
            client_id=ctr_client_id
            client_password=ctr_client_password
        return(client_id,client_password)
    if service=="kenna":
        if kenna_token=='paste_kenna_token_here':
            with open('../keys/kenna.txt') as creds:
                access_token=creds.read()
                #print(access_token)          
        else:
            access_token=kenna_token   
        return(access_token)

def get_ctr_token(host_for_token,client_id,client_password):
    print(yellow('Asking for new CTR token',bold=True))
    url = f'{host_for_token}/iroh/oauth2/token'
    #url = 'https://visibility.eu.amp.cisco.com/iroh/oauth2/token'
    print()
    print(url)
    print()    
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    #client_id,client_password=read_api_keys('ctr')
    print()
    print(green(client_id,bold=True))
    print(green(client_password,bold=True))
    response = requests.post(url, headers=headers, auth=(client_id, client_password), data=payload)
    #print(response.json())
    reponse_list=response.text.split('","')
    token=reponse_list[0].split('":"')
    print(token[1])
    fa = open("ctr_token.txt", "w")
    fa.write(token[1])
    fa.close()
    return (token[1])


    
def current_date_time():
    current_time = datetime.utcnow()
    current_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return(current_time)
    
def current_date_time_simple():
    current_time = datetime.utcnow()
    current_time = current_time.strftime("%Y-%m-%dT%H:%M:%S")
    return(current_time)
    
def date_plus_x_days(nb):  
    '''
        working example
    '''
    current_time = datetime.utcnow()
    start_time = current_time + timedelta(days=nb)
    timestampStr = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return(timestampStr)
    
def create_event_bunble_json_bak():
    '''
        create the incident with a sighthing - ORIGINAL OK for SecureX
    '''
    # Bundle global
    source_ref="transient:patrick-sighting-bbcde36fe2c678aa969162272ed8e8ac215f7705b13f4e2530d1c572a9"
    target_ref="transient:patrick-incident-bbcde9024ffecb353db95ce9cbce57ce7c7de01358a5e39c5950d8fbafe"
    # Incident definition
    incident_severity="Critical"    
    incident_short_description="Infection example for XDR Demo"
    time=current_date_time_simple()
    incident_title="XDR Endpoint Infection demo"    
    incident_description=f"| Incident Title | LAPTOP SEVERE INFECTION |\n| - | - |\n| Promoted at | {time} UTC |\n| Promotion method | Automated |\n| Indicators | **Possible Powershell Post-Exploitation Loader**: Several PowerShell-based post exploitation frameworks such as PowerShell Empire and CobaltStrike loaders decode and run byte code in memory, which is often also compressed and base64-encoded. A PowerShell command similar to such frameworks was executed. |\n| MITRE Tactics | [TA0005](https://attack.mitre.org/tactics/TA0005): Defense Evasion<br>[TA0002](https://attack.mitre.org/tactics/TA0002): Execution |\n| MITRE Techniques | [T1059.001](https://attack.mitre.org/techniques/T1059/001): PowerShell |\n| Host name | Victim Laptop |\n| GUID | 57150e86-fcbe-47ff-8bc7-3f297d473b79 |\n| Operating System | Windows 10 Connected (Build 9600.19893) |\n| Group | Protect_Group |\n| Policy | Protect_Policy |\n| Internal IP | 192.168.0.137 |\n| External IP | 84.48.25.16 |\n"
    incident_source_uri='https://console.eu.amp.cisco.com/computers/57150e86-fcbe-47ff-8bc7-3f297d473b79/trajectory2'
    incident_confidence="High"   
    discovery_method="Automated detection by Secure Endpoint"
    promotion_method="Automated" # Manual or Automated    
    #Sighting Definition
    sighting_title= "Suspicious connection to server"
    source="XDR Demo"
    source_uri="https://www.cisco.com/c/en/us/products/security/cyber-vision/index.html"
    relationship_type="member-of"
    sighting_id="patrick-incident-bbcde9024ffecb353db95ce9cbce57ce7c7de01358a5e39c5950d8fbafe"
    sighting_source_uri="https://www.google.com"
    sighting_severity="High"
    sighting_confidence="High"
    sensor='endpoint'    
    target='endpoint'
    #//////////////////////////////
    # Here under the JSON data
    json_data={"type":"bundle",
    "source":source,
    "source_uri":source_uri,
    "relationships":[
        {
            "type":"relationship",
            "source":source,
            "source_uri":source_uri,
            "relationship_type":relationship_type,
            "source_ref":source_ref,
            "target_ref":target_ref
        }      
        ],
    "sightings":[
            {
                "id":source_ref,
                "title": sighting_title,
                "type":"sighting",
                "external_ids":[source_ref],
                "source":source,
                "source_uri":sighting_source_uri,
                "severity":sighting_severity,
                "confidence":sighting_confidence,
                "observed_time":
                    {"start_time":current_date_time()},
                "sensor":sensor,
                "sensor_coordinates":{
                    "type":sensor,
                    "observables":[
                                {"type":"ip","value":"192.168.69.22"},
                                {"type":"device","value":"Example of string Device Identifier"}
                        ]
                    },
                "observables":[
                        {"type":"ip","value":"91.109.190.8"}
                    ],
                "relations":[
                        {"source":{"type":"ip","value":"91.109.190.8"},"related":{"type":"ip","value":"84.48.25.16"},"relation":"Connected_To","origin":"Sensor XYZ"}
                    ],
                "targets":[
                    {"type":target,
                    "observables":[
                        {"type":"ip","value":"84.48.25.16"}
                        ],
                        "observed_time":
                        {"start_time":current_date_time()}
                    }
                ]
            }          
        ],
    "incidents":[
            {"id":target_ref,
            "type":"incident",
            "external_ids":[target_ref],
            "source":source,
            "source_uri":incident_source_uri,
            "title":incident_title,
            "short_description":incident_short_description,
            "description":incident_description,
            "confidence":incident_confidence,
            "severity":incident_severity,
            "status":"New",
            "incident_time":{"opened":current_date_time(),"discovered":current_date_time()},
            "categories":[categories[3]],
            "discovery_method":discover_method[2],
            "promotion_method":promotion_method
            }
        ]
    }
    return(json_data)
    
def create_event_bunble_json():
    '''
        create a new XDR incident with a sighthing DEV
    '''
    # Bundle global
    source_ref="transient:patrick-sighting-cccde36fe2c678aa969162272ed8e8ac215f7705b13f4e2530d1c572a9"
    target_ref="transient:patrick-incident-cccde9024ffecb353db95ce9cbce57ce7c7de01358a5e39c5950d8fbafe"
    # Incident definition
    incident_severity="Critical"    
    incident_short_description="Infection example for XDR Demo"
    time=current_date_time_simple()
    incident_title="XDR Endpoint Infection demo"    
    incident_description=f"| Incident Title | LAPTOP SEVERE INFECTION |\n| - | - |\n| Promoted at | {time} UTC |\n| Promotion method | Automated |\n| Indicators | **Possible Powershell Post-Exploitation Loader**: Several PowerShell-based post exploitation frameworks such as PowerShell Empire and CobaltStrike loaders decode and run byte code in memory, which is often also compressed and base64-encoded. A PowerShell command similar to such frameworks was executed. |\n| MITRE Tactics | [TA0005](https://attack.mitre.org/tactics/TA0005): Defense Evasion<br>[TA0002](https://attack.mitre.org/tactics/TA0002): Execution |\n| MITRE Techniques | [T1059.001](https://attack.mitre.org/techniques/T1059/001): PowerShell |\n| Host name | Patrick_Laptop |\n| GUID | 57150e86-fcbe-47ff-8bc7-3f297d473b79 |\n| Operating System | Windows 8.1 Connected (Build 9600.19893) |\n| Group | Patrick_Group |\n| Policy | Audit_Patrick |\n| Internal IP | 192.168.0.137 |\n| External IP | 84.48.25.16 |\n"
    incident_source_uri='https://console.eu.amp.cisco.com/computers/57150e86-fcbe-47ff-8bc7-3f297d473b79/trajectory2'
    incident_confidence="High"   
    discovery_method="Automated detection by Secure Endpoint"
    promotion_method="Automated" # Manual or Automated    
    #Sighting Definition
    sighting_title= "Suspicious connection to server"
    source="XDR Demo"
    source_uri="https://www.cisco.com/c/en/us/products/security/cyber-vision/index.html"
    relationship_type="member-of"
    sighting_id="patrick-incident-cccde9024ffecb353db95ce9cbce57ce7c7de01358a5e39c5950d8fbafe"
    sighting_source_uri="https://www.google.com"
    sighting_severity="High"
    sighting_confidence="High"
    sensor='endpoint'    
    target='endpoint'
    #//////////////////////////////

    # Here under the JSON data
    json_data={"type":"bundle",
    "source":source,
    "source_uri":source_uri,
    "relationships":[
        {
            "type":"relationship",
            "source":source,
            "source_uri":source_uri,
            "relationship_type":relationship_type,
            "source_ref":source_ref,
            "target_ref":target_ref
        }      
        ],
    "sightings":[
            {
                "id":source_ref,
                "title": sighting_title,
                "type":"sighting",
                "external_ids":[source_ref],
                "source":source,
                "source_uri":sighting_source_uri,
                "severity":sighting_severity,
                "confidence":sighting_confidence,
                "observed_time":
                    {"start_time":current_date_time()},
                "sensor":sensor,
                "sensor_coordinates":{
                    "type":sensor,
                    "observables":[
                                {"type":"ip","value":"192.168.69.22"},
                                {"type":"device","value":"Example of string Device Identifier"}
                        ]
                    },
                "observables":[
                        {"type":"ip","value":"91.109.190.8"}
                    ],
                "relations":[
                        {"source":{"type":"ip","value":"91.109.190.8"},"related":{"type":"ip","value":"84.48.25.16"},"relation":"Connected_To","origin":"Sensor XYZ"}
                    ],
                "targets":[
                    {"type":target,
                    "observables":[
                        {"type":"ip","value":"84.48.25.16"}
                        ],
                        "observed_time":
                        {"start_time":current_date_time()}
                    }
                ]
            }          
        ],
    "incidents":[
            {
                "id":target_ref,
                "title":incident_title,
                "description":incident_description,
                "short_description":incident_short_description,            
                "type":"incident",
                "schema_version": "1.3.5",
                "external_ids":[target_ref],
                "source":source,
                "source_uri":incident_source_uri,
                "confidence":incident_confidence,
                "status":"New",
                "incident_time":{"opened":current_date_time(),"discovered":current_date_time()},
                "techniques": [
                    "T1102"
                    ],
                "tactics": [
                        "TA0043",
                        "TA0011",
                        "TA0001"
                    ],
                "external_references": [
                        {
                            "source_name": "Cisco XDR APIs",
                            "url": "https://developer.cisco.com/docs/cisco-xdr/"
                        }
                    ],
                "scores": {
                    "asset": 10,
                    "ttp": 95,
                    "global": 950
                }                    
            }
        ]
    }
    return(json_data)
    
def add_sighting_to_incident_bunble_json():
    '''
        add a sighthing to the existing incident
    '''
    # Bundle global
    source_ref="transient:patrick-sighting-aacde36fe2c678aa969162272ed8e8ac215f7705b13f4e2530d1c572a9"
    target_ref="transient:patrick-incident-bbcde9024ffecb353db95ce9cbce57ce7c7de01358a5e39c5950d8fbafe"
    # Incident definition
    incident_severity="Critical"    
    incident_short_description="Infection example for XDR Demo"
    time=current_date_time_simple()
    incident_title="XDR Endpoint Infection demo"    
    incident_description=f""
    incident_source_uri='https://console.eu.amp.cisco.com/computers/57150e86-fcbe-47ff-8bc7-3f297d473b79/trajectory2'
    incident_confidence="High"   
    discovery_method="Automated detection by Secure Endpoint"
    promotion_method="Automated" # Manual or Automated    
    #Sighting Definition
    sighting_title= "Possible Powershell Post-Exploitation Loader"
    source="XDR Demo"
    source_uri="https://www.cisco.com/c/en/us/products/security/cyber-vision/index.html"
    relationship_type="member-of"
    sighting_id="patrick-incident-bbcde9024ffecb353db95ce9cbce57ce7c7de01358a5e39c5950d8fbafe"
    sighting_source_uri="https://www.google.com"
    sighting_severity="High"
    sighting_confidence="High"
    sensor='endpoint'    
    target='endpoint'
    #//////////////////////////////

    # Here under the JSON data
    json_data={"type":"bundle",
    "source":source,
    "source_uri":source_uri,
    "relationships":[
        {
            "type":"relationship",
            "source":source,
            "source_uri":source_uri,
            "relationship_type":relationship_type,
            "source_ref":source_ref,
            "target_ref":target_ref
        }      
        ],
    "sightings":[
            {                
                "id":source_ref,
                "title": sighting_title,
                "type":"sighting",
                "external_ids":[source_ref],
                "source":source,
                "source_uri":"https://console.eu.amp.cisco.com/computers/57150e86-fcbe-47ff-8bc7-3f297d473b79/trajectory2?_ts=1669279034647&id=7169498858928483382",
                "severity":"High",
                "confidence":"High",
                "observed_time":
                    {"start_time":current_date_time()},
                "sensor":"endpoint",
                "sensor_coordinates":{
                    "type":"endpoint",
                    "observables":[
                                {"type":"ip","value":"192.168.69.22"}
                        ]
                    },
                "observables":[
                        {"type":"sha256","value":"6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b"},
                        {"type":"sha256","value":"54c0cd40ea153f2b8cdc27c1b1baf96d77505807bda9979f2ba9ccb7ff0db3ed"}
                    ],
                "targets":[
                    {"type":"endpoint",
                    "observables":[
                        {"type":"ip","value":"84.48.25.16"},
                        {"type":"hostname","value":"Victim Endpoint"},
                        {"type":"amp_computer_guid","value":"57150e86-fcbe-47ff-8bc7-3f297d473b79"},
                        {"type":"hostname","value":"Victim Endpoint"},
                        {"type":"ip","value":"192.168.0.137"}
                        ],
                        "observed_time":
                        {"start_time":current_date_time()}
                    }
                ]
            }           
        ],
    "incidents":[
            {"id":target_ref,
            "type":"incident",
            "external_ids":[target_ref],
            "source":source,
            "source_uri":incident_source_uri,
            "title":incident_title,
            "incident_time":{"opened":current_date_time(),"discovered":current_date_time()},
            "confidence":incident_confidence,
            "severity":incident_severity,
            "status":"New",
            "incident_time":{"opened":current_date_time(),"discovered":current_date_time()},
            "categories":[categories[3]],
            "discovery_method":discover_method[2],
            "promotion_method":promotion_method            
            }
        ]
    }
    return(json_data)

        
def create_incident_with_sightings(host,host_for_token,ctr_client_id,ctr_client_password):
    fa = open("ctr_token.txt", "r")
    access_token = fa.readline()
    fa.close() 
    '''
        create new incident with one sighting and add a second sigthing into it
    '''
    incident_json=create_event_bunble_json()
    print()
    print(incident_json)
    print()
    print("Let's connect to CTIA and Create the Incident")
    print()
    url = f"{host_for_token}/iroh/private-intel/bundle/import?external-key-prefixes=sxo" 
    #url = f"{host}/iroh/private-intel/bundle/import" 
    print()
    print(url)
    print()    
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, data=json.dumps(incident_json),headers=headers)
    print()  
    if response.status_code==401:
        print("Asking for a Token") 
        access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
        headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}        
        response = requests.post(url, data=json.dumps(incident_json),headers=headers)  
        print(response.status_code) 
    elif response.status_code!=200:
        print(red(response.status_code,bold=True)) 
        print()         
        print(red("Error !",bold=True))    
        print(response.json())  
        print()        
    else:
        print(green(response.status_code,bold=True)) 
        print()         
        print("Ok Done")         
        print()    
    #print(response.json())    
    '''
    print()
    print("Now let's add another sighting to the incident")
    print()      
    incident_json=add_sighting_to_incident_bunble_json()
    print()
    print(incident_json)
    print()
    print("Let's connect to CTIA for adding the sighting into the existing incident")
    print()
    #url = f"{host}/iroh/private-intel/bundle/import?external-key-prefixes=sxo" 
    #headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, data=json.dumps(incident_json),headers=headers)
    print()  
    if response.status_code==401:
        print("Asking for a Token") 
        access_token=get_ctr_token(host_for_token)
        headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}        
        response = requests.post(url, data=json.dumps(incident_json),headers=headers)  
        print(response.status_code) 
    elif response.status_code!=200:
        print(red(response.status_code,bold=True)) 
        print()         
        print(red("Error !",bold=True))    
        print(response.json())  
        print()        
    else:
        print(green(response.status_code,bold=True)) 
        print()         
        print("Ok Done")         
        print()   
    '''
    return 1

'''    
if __name__=="__main__":
    create_incident_with_sightings(host)
'''
