# version 20221211
import requests
import time
import sys
from crayons import *

def read_api_keys(service):   
    # read API credentials from an external file on this laptop ( API keys are not shared with the flask application )
    global ctr_client_id
    global ctr_client_password
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

def ask_for_ctr_token(host_for_token,client_id,client_password):
    url = f'{host_for_token}/iroh/oauth2/token'
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    #client_id,client_password=read_api_keys('ctr') 
    print()
    print("URL : ",url)
    print("client_id : ",client_id)
    print("client_password :",client_password)  
    print()    
    #sys.exit()
    response = requests.post(url, headers=headers, auth=(client_id, client_password), data=payload)
    print()
    #print(response.json())
    if response.status_code==200:
        reponse_list=response.text.split('","')
        token=reponse_list[0].split('":"')
        print(token[1])
        fa = open("ctr_token.txt", "w")
        fa.write(token[1])
        fa.close()
        return token[1]
    else:
        print(red("ERROR Can't Get CTR Token",bold=True))
        return 0
        
def get(host_for_token,access_token,url):    
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    url = f"{host_for_token}{url}?limit=5"
    response = requests.get(url, headers=headers)
    return response
    
def get_incidents(access_token,host_for_token):
    url = "/ctia/incident/search"
    response = get(host_for_token,access_token,url)
    print(response.status_code)
    if response.status_code==200:
        print(green("Success I can Get Incidents",bold=True))
        return 1
    else:
        print(red("ERROR Can't Get Incidents",bold=True))
        return 0    
    
def check_secureX(host_for_token,client_id,client_password):
    access_token=ask_for_ctr_token(host_for_token,client_id,client_password)
    if access_token:
        if get_incidents(access_token,host_for_token):
            return 1
        else:
            return 0
    else:
        return 2
'''
if __name__=='__main__':
    url = f'{host_for_token}/iroh/oauth2/token'
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    client_id,client_password=read_api_keys('ctr') 
    print(client_id)
    print(client_password)   
    #sys.exit()
    response = requests.post(url, headers=headers, auth=(client_id, client_password), data=payload)
    #print(response.json())
    reponse_list=response.text.split('","')
    token=reponse_list[0].split('":"')
    print(token[1])
    fa = open("ctr_token.txt", "w")
    fa.write(token[1])
    fa.close()
'''