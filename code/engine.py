from webex_bot.models.command import Command
from webex_bot.models.response import Response
#import logging
import requests
import json
from alert_card import create_card_content
from crayons import *
from add_observable_to_XDR_feeds import add_observable_to_feed

#log = logging.getLogger(__name__)

class cmd(Command):
    def __init__(self):
        super().__init__(
            command_keyword="temp",
            help_message="Ask Service to XDR",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        # message will contain the word given after temp : ex paris is we type temp paris into the bot room
        r = requests.get("https://prevision-meteo.ch/services/json/paris")
        json_raw = r.content
        parsed_json = json.loads(json_raw)
        #print(json.dumps(parsed_json, indent = 4, sort_keys=True))
        #print(parsed_json)
        temp_act = (parsed_json['current_condition']['tmp'])
        print('current temparture in Paris : ',temp_act)    
        return f"current temparture in Paris is : {temp_act} Degrees"
        
class cmd2(Command):
    def __init__(self):
        super().__init__(
            command_keyword="alert",
            help_message="Ask Service to XDR",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        alert_message="Suspicious Activity Detected"
        cards_content=create_card_content(alert_message)
        #card_payload = json.dumps(cards_content[0])
        response = Response()
        response.text = "Test Card"
        # Attachments being sent to user
        response.attachments = cards_content[0]
        return response
 
class cmd3(Command):
    def __init__(self):
        super().__init__(
            command_keyword="targets",
            help_message="get targets",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        targets=attachment_actions.inputs['targets']
        return f"Selected Targets to isolate are : {targets} "
        
class cmd4(Command):
    def __init__(self):
        super().__init__(
            command_keyword="observables",
            help_message="get observables",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        observables=attachment_actions.inputs['observables']
        print('observables received from formular : ',yellow(observables,bold=True))
        observables=observables.split(',') 
        for observable in observables:
            print('Observable to add to feed : ',cyan(observable,bold=True))
            add_observable_to_feed(observable)
        return f"following observables were added to XDR feed : {observables} "
        
class cmd5(Command):
    def __init__(self):
        super().__init__(
            command_keyword="stop",
            help_message="Stop Server",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        response = requests.get("http://localhost:4000/stop")
        return f"Stopping Web Server"
        