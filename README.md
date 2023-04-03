# EDRKillSwitch
Graphical utility for handling rapid isolation and restoration of Fortinet EDR collectors

This script and its GUI were designed to allow an organization to rapidly isolate collectors in the event that a particularly virulent form of malware is deployed within an organization. 

Disclaimer: Use with caution. Reckless use of this application in a production environment may result in a high volume of inbound tickets and an abrupt career transition to panhandling and vagrancy

Instructions for use:

1) Create an administrative API user in the manager system
2) Encode the username and password in Base64 and transmit them to the manager via Curl (See Fortinet documentation for exact instructions)
3) If the request is successful, retrieve the API Key from the response headers
4) Open the application EDRKillSwitch.exe or EDRKillSwitch.py
5) Embed the manager IP or FQDN in the appropriate field
6) Embed the API key in the appropriate field
7) Click 'Set Parameters'
8) Acknowledge the confirmation dialogue
9) Pending successful verification of the parameters, isolate and restore as required

![image](https://user-images.githubusercontent.com/24815431/229586747-b4823625-7046-48e3-8d06-b508a7c9ef78.png)
