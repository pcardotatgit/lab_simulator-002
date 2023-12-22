'''
     for testing sending message Thru SecureX Webhook to webex team room with bot token
    v20231213
'''
import requests
from crayons import *

SecureX_Webhook_url=""
DESTINATION_ROOM_ID=""
BOT_ACCESS_TOKEN=""

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

def send_webhook(ip):
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    body_message={'message':'Hello Message sent in the body'}

    body_message={
        "list_of_ips": [ip],
        "roomId":DESTINATION_ROOM_ID,
        "webex_bot_token":BOT_ACCESS_TOKEN
    }
    print()
    print(cyan(f'Webhook_url : {SecureX_Webhook_url}',bold=True))
    print()
    try:
        print(cyan(f"Trigger SecureX webhook for ip : {ip}",bold=True))
        response = requests.post(SecureX_Webhook_url, headers=headers,data=body_message)
        print(response)
        if response.status_code==202:
            print(green("Webhook Succesfuly sent to SecureX {FLAG:your_are_on_the_road}",bold=True))
            return 1 
        elif response.status_code==401:
            print(red("Error with SecureX webhook probable Bad webhook URL",bold=True))
            return 1             
        else:
            print(red("Webhook Not sent : Unkown Error ( token is ok )",bold=True))
            return 0           
    except:
        response.raise_for_status()
        print(red("Webhook SecureX failed",bold=True))
        return 0

if __name__=="__main__":
    with open('config.txt','r') as file:
        text_content=file.read()
    ctr_client_id,ctr_client_password,host,SecureX_Webhook_url,DESTINATION_ROOM_ID,BOT_ACCESS_TOKEN,host_for_token = parse_config(text_content)
    send_webhook("20.20.20.20")