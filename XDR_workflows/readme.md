## XDR Demo Incident workflow - Send Alert to Webex Room

This workflow is attached to the XDR demo. This is an Incident workflow that is automatically triggered when a New XDR Incident with **source=XDR Demo** is created.

Then this workflow parse this new incident and extracts targets and observables. Two separated variables are created that contain targets in one side in a list with one object per line. And the same for observables.

Both list are then passed to the [**XDR_ALERT_CARD_WITH_TARGETS_AND_OBSERVABLES_TO_WEBEX_ROOM**](https://github.com/pcardotatgit/webex_for_xdr_part-6_XDR_send_alert_workflow) which is actually included into this current workflow.

The result is that the Advanced Alert Webex Card described into the [**XDR_ALERT_CARD_WITH_TARGETS_AND_OBSERVABLES_TO_WEBEX_ROOM**](https://github.com/pcardotatgit/webex_for_xdr_part-6_XDR_send_alert_workflow) article, is sent into the Alert Bot Webex Room with targets and observables contained into the Incident.

You must install this workflow into your XDR tenant.

And you must assign the correct value to the following global XDR variables :

- **XDR_ALERT_BOT_ROOM_ID**
- **XDR_ALERT_BOT_TOKEN**

## How it works ?

When a XDR Incident with **source=XDR Demo** is created ( which the simulator actually does ) the workflow is automatically triggered and an Alert Card is send into the BOT Webex Room.

The workflow only does this. Next steps are not managed by the workflow.