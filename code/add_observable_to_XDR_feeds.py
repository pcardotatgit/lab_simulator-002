import sys
from crayons import *
import requests
import json
from datetime import datetime, date, timedelta

ctr_client_id=""
ctr_client_password=""
host=""
host_for_token=""

def parse_config(text_content):
    text_lines=text_content.split('\n')
    conf_result=['','','','','','','']
    for line in text_lines:
        print(green(line,bold=True))
        if 'ctr_client_id' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[0]=line.split('=')[1]
                conf_result[0]=conf_result[0].replace('"','')
                conf_result[0]=conf_result[0].replace("'","")
            else:
                conf_result[0]=""
        elif 'ctr_client_password' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[1]=line.split('=')[1]
                conf_result[1]=conf_result[1].replace('"','')
                conf_result[1]=conf_result[1].replace("'","")
            else:
                conf_result[1]=""        
        elif '.eu.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.eu.amp.cisco.com"  
            conf_result[6]="https://visibility.eu.amp.cisco.com"
        elif '.intel.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.amp.cisco.com"   
            conf_result[6]="https://visibility.amp.cisco.com"
        elif '.apjc.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.apjc.amp.cisco.com"
            conf_result[6]="https://visibility.apjc.amp.cisco.com"
        elif 'SecureX_Webhook_url' in line:
            words=line.split('=')
            if len(words)==2:        
                print(yellow(words))        
                conf_result[3]=words[1]
                conf_result[3]=conf_result[3].replace('"','')
                conf_result[3]=conf_result[3].replace("'","")                
            else:
                conf_result[3]=""
        elif 'webex_bot_token' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[5]=line.split('=')[1]
                conf_result[5]=conf_result[5].replace('"','')
                conf_result[5]=conf_result[5].replace("'","")
            else:
                conf_result[5]=""        
        elif 'webex_room_id' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[4]=line.split('=')[1]
                conf_result[4]=conf_result[4].replace('"','')
                conf_result[4]=conf_result[4].replace("'","")
            else:
                conf_result[4]=""        
    print(yellow(conf_result))
    return conf_result
    
def get_ctr_token(host_for_token,ctr_client_id,ctr_client_password):
    print(yellow('Asking for new CTR token',bold=True))
    url = f'{host_for_token}/iroh/oauth2/token'
    #url = 'https://visibility.eu.amp.cisco.com/iroh/oauth2/token'
    print()
    print(url)
    print()    
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    print()
    print('ctr_client_id : ',green(ctr_client_id,bold=True))
    print('ctr_client_password : ',green(ctr_client_password,bold=True))
    response = requests.post(url, headers=headers, auth=(ctr_client_id, ctr_client_password), data=payload)
    #print(response.json())
    reponse_list=response.text.split('","')
    token=reponse_list[0].split('":"')
    print(token[1])
    fa = open("ctr_token.txt", "w")
    fa.write(token[1])
    fa.close()
    return (token[1])

def disposition_name(disposition):
    #{"Common Unknow Suspicious Malicious Clean 
    disposition_name = ""
    if disposition == 1:
    	disposition_name = "Clean"
    elif disposition == 2:
    	disposition_name = "Malicious"
    elif disposition == 3:
    	disposition_name = "Suspicious"
    elif disposition == 4:
    	disposition_name = "Common"
    elif disposition == 5:
    	disposition_name = "Unknown"
    return disposition_name
    
def disposition_value(disposition_name):
    disposition = ""
    if disposition_name == "Clean":
    	disposition = 1
    elif disposition_name == "Malicious":
    	disposition = 2
    elif disposition_name == "Suspicious":
    	disposition = 3
    elif disposition_name == "Common":
    	disposition = 4
    elif disposition_name == "Unknown":
    	disposition = 5
    return disposition
    
def inspect(observable,access_token,host_for_token):
    url=f"{host_for_token}/iroh/iroh-inspect/inspect"
    inspect_payload={ "content": observable }
    inspect_payload = json.dumps(inspect_payload)
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, headers=headers,data=inspect_payload)
    rep = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    #print(rep)
    return (rep)
    
def which_indicator(observable,host_for_token,access_token):
    if observable['type']=='ip':
        indicator="Secure_Firewall_SecureX_Indicator_IPv4"
    elif observable['type']=='ipv6':
        indicator="Secure_Firewall_SecureX_Indicator_IPv6"
    elif observable['type']=='url':
        indicator="Secure_Firewall_SecureX_Indicator_URL"  
    elif observable['type']=='domain':
        indicator="Secure_Firewall_SecureX_Indicator_Domain" 
    elif observable['type']=='sha256':
        indicator="Secure_Firewall_SecureX_Indicator_SHA256"  
    #print()
    #print("indicator : ",indicator)        
    #print()
    url=f"{host_for_token}/ctia/indicator/search?limit=1&offset=0&query=title:{indicator}"
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.get(url, headers=headers)
    rep = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    #print(response.json()[0]['id'])
    print(response.json())
    if response.status_code==200 or response.status_code==201:
        if len(response.json()) ==0: 
            return 1
        else:
            return response.json()[0]['id']
    else:
        return 0    


def create_judgment_json(value,type,source,disposition_name,reason,priority,severity,tlp,confidence):
    # Get the current date/time
    dateTime = datetime.now()

    # Build the judgement object
    judgment_object = {}
    judgment_object["schema_version"] = "1.0.19"
    judgment_object["observable"] = {
    	"value": value,
    	"type": type
    }
    judgment_object["type"] = "judgement"
    judgment_object["source"] = source
    judgment_object["disposition"] = disposition_value(disposition_name)
    judgment_object["reason"] = reason
    judgment_object["disposition_name"] = disposition_name
    judgment_object["priority"] = priority
    judgment_object["severity"] = severity
    judgment_object["tlp"] = tlp
    judgment_object["timestamp"] = dateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
    judgment_object["confidence"] = confidence
    judgment_json = json.dumps(judgment_object)
    return(judgment_json)
    
def create_judgment(payload,host,access_token):
    url = f'{host}/ctia/judgement'
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    #payload = json.dumps(judgment_json)
    response = requests.post(url, headers=headers, data=payload)
    print()
    print (yellow(response,bold=True))  
    print()
    #print(green(response.json(),bold=True))
    rep = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    print(green(rep,bold=True))
    if response.status_code==200 or response.status_code==201:
        return response.json()['id']
    else:
        return 0

def create_relationship(json_payload,access_token,host):
    url=f"{host}/ctia/relationship"
    #inspect_payload={ "content": observable }
    #inspect_payload = json.dumps(inspect_payload)
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, headers=headers,data=json_payload)
    rep = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    print(cyan(rep,bold=True))
    if response.status_code==200 or response.status_code==201:
        return 1
    else:
        return 0    
    
def create_json_for_relationship(source,relationship_type,tlp,judgment_id,indicator_id,description,short_description,title):
    dateTime = datetime.now()
    # Build the relationship object
    relationship_object = {}
    relationship_object["description"] = description
    relationship_object["schema_version"] = "1.0.11"
    relationship_object["target_ref"] = indicator_id
    relationship_object["type"] = "relationship"
    relationship_object["source"] = source
    relationship_object["short_description"] = short_description
    relationship_object["title"] = title
    relationship_object["source_ref"] = judgment_id
    relationship_object["tlp"] = tlp
    relationship_object["timestamp"] = dateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
    relationship_object["relationship_type"] = relationship_type
    relationship_json = json.dumps(relationship_object)
    return (relationship_json)
        
def add_observable_to_feed(object_to_add_to_feed):
    print(yellow("Step 0 read config file",bold=True))
    with open('config.txt','r') as file:
        text_content=file.read()
    ctr_client_id,ctr_client_password,host,SecureX_Webhook_url,DESTINATION_ROOM_ID,BOT_ACCESS_TOKEN,host_for_token = parse_config(text_content)
    print()
    print('ctr_client_id :',ctr_client_id)
    print('ctr_client_password :',ctr_client_password)
    print('host : ',host )
    #print('SecureX_Webhook_url :',SecureX_Webhook_url)
    #print('BOT_ACCESS_TOKEN : ',BOT_ACCESS_TOKEN)
    #print('DESTINATION_ROOM_ID : ',DESTINATION_ROOM_ID)
    print('host_for_token : ',host_for_token) 
    print(yellow("Step 1 check if CTR access token valid",bold=True))
    fa = open("ctr_token.txt", "r")
    access_token = fa.readline()
    fa.close()     
    offset=0
    limit=10    
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    url = f"{host}/ctia/incident/search?limit={limit}&offset={offset}"
    response = requests.get(url, headers=headers)    
    if response.status_code!=200:
        print(yellow("Step 1 ask for an access token to CTR",bold=True))
        access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
        print(green("Ok Token = Success",bold=True))
    else:
        print(green("Token is valid. Let's move forward",bold=True))
        print()
    print(yellow("Step 2 Let's get observable type ",bold=True))
    print()
    #object_to_add_to_feed=input('Enter the value of the object to add to feeds : ')
    rep=inspect(object_to_add_to_feed,access_token,host_for_token)
    rep=json.loads(rep)
    print(yellow(rep[0]))
    print(yellow("Step 3 Let's get Indicator ID ",bold=True))
    indicator_id=which_indicator(rep[0],host,access_token)
    if indicator_id==0:
        print(red("Error : Can't connect to CTR !",bold=True))
        sys.exit()
    if indicator_id==1:
        print(red("Error : No Indicator Found. You must create it first !",bold=True))      
        sys.exit()
    print()
    print('indicator_id : ',cyan(indicator_id,bold=True))
    print(yellow("Step 4 Let's create a new judgment ",bold=True))
    source='XDR Demo'
    disposition_name='Malicious'
    reason='Infection Demo'
    priority=95
    severity="Info"
    tlp="amber"
    confidence = "High"
    response=create_judgment_json(rep[0]['value'],rep[0]['type'],source,disposition_name,reason,priority,severity,tlp,confidence)
    print(cyan(response,bold=True))
    judgment_id=create_judgment(response,host,access_token)
    print('judgment_id : ',judgment_id)
    print()
    print(yellow("Step 5 Let's link the judgment to the indicator with a relationship",bold=True))
    print()
    print('- Source Object ( Judgment ID ) : ',cyan(judgment_id,bold=True) )
    print('- Relationship type :',cyan('element-of ',bold=True))
    print('- Target Object ( Indicator ID ) : ',cyan(indicator_id,bold=True) )
    print()
    title='Relationship for linking observable to feed'
    description="Relationship for linking observable to feed"
    short_description="Relationship for linking observable to feed"
    relationship_type="element-of"
    relationship_json=create_json_for_relationship(source,relationship_type,tlp,judgment_id,indicator_id,description,short_description,title)
    print('- JSON payload for relationship : ',cyan(relationship_json,bold=True))
    print()
    result=create_relationship(relationship_json,access_token,host)
    print()
    if result:
        print(green("SUCCESS. Observable was added to it's XDR Feed ",bold=True))
        return 1
    else:
        print(red("ERROR. Couldn't the Observable to it's XDR Feed ",bold=True))
        return 0

        
