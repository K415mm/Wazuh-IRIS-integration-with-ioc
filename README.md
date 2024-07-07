# Wazuh-IRIS-integration-with-ioc
Wazuh IRIS integration with ioc
Wazuh Integration Script for IRIS DFIR with IoC Extraction
This Python script provides a custom integration between Wazuh and IRIS DFIR. It enriches Wazuh alerts with extracted Indicators of Compromise (IoCs) and sends them to IRIS DFIR for further investigation.

Features:

Extracts potential IoCs (MD5, SHA1, IP address, hostname, URL) from Wazuh alerts.
Formats alert details for better readability in IRIS DFIR.
Maps Wazuh rule levels to IRIS severity levels.
Sends enriched alerts to IRIS DFIR via a POST request with authentication.
Logs information about sent alerts and any errors.
Requirements:
```
Wazuh server with alerts enabled
IRIS DFIR account with API access

```
Setup:

Save the script as custom-wazuh_iris.py on your Wazuh server.

Make the script executable:
 ```
chmod +x /var/ossec/integrations/custom-wazuh_iris.py
chown root:wazuh /var/ossec/integrations/custom-wazuh_iris.py

```

Configure Wazuh to use this script:

Edit your Wazuh configuration file:
```
 sudo nano /var/ossec/etc/ossec.conf

 ```

Add an integration block similar to this (replace placeholders with your values):

XML
```
<integration>
    <name>custom-wazuh_iris.py</name>
    <hook_url>/var/ossec/integrations/custom-wazuh_iris.py</hook_url>  # Path to your script
    <api_key>YOUR_IRIS_DFIR_API_KEY</api_key>  # Replace with your IRIS DFIR API key
    <level>7</level>  # Filter for alerts with severity level 7 or higher (optional)
    <alert_format>json</alert_format>
</integration>

```
Use code with caution.
content_copy
Restart the Wazuh agent:
```
service wazuh-agent restart

```

Customization:

You can adjust the ioc_types dictionary in the search_ioc function to search for different types of IoCs.
Modify the severity level mapping in the main function to match your preference.
Update the alert_source_link in the payload to point to your actual Wazuh dashboard IP address.
Consider adding more sophisticated logic for extracting IoCs, especially for URLs.
How it Works:

When a Wazuh alert is triggered, the script is called with the alert data as a JSON file.
The script extracts relevant information from the alert, including potential IoCs.
It formats the alert details and maps the severity level.
An enriched payload containing the alert information and IoCs is constructed.
The script sends a POST request to the IRIS DFIR API to create a new alert.
The script logs the response status code and any errors encountered.
For further details and troubleshooting, refer to the script source code.
