# Wazuh-IRIS-integration-with-ioc
Custom Wazuh Integration Script for DFIR-IRIS
Wazuh IRIS integration with ioc
Wazuh Integration Script for IRIS DFIR with IoC Extraction
This Python script provides a custom integration between Wazuh and IRIS DFIR. It enriches Wazuh alerts with extracted Indicators of Compromise (IoCs) and sends them to IRIS DFIR for further investigation.

Features:

Extracts potential IoCs (MD5, SHA1, IP address, hostname, URL ...) from Wazuh alerts.
Formats alert details for better readability in IRIS DFIR.
Maps Wazuh rule levels to IRIS severity levels.
Sends enriched alerts to IRIS DFIR.
Logs information about sent alerts and any errors.
Requirements:
```
Wazuh server with alerts enabled
IRIS DFIR account with API access

```
Setup:

Save the script as custom-wazuh_iris2.py on your Wazuh server.

Make the script executable:
 ```
chmod +x /var/ossec/integrations/custom-wazuh_iris2.py
chown root:wazuh /var/ossec/integrations/custom-wazuh_iris2.py
chmod -R +x /var/ossec/integrations/cxsoar_kmod
chown -R root:wazuh /var/ossec/integrations/cxsoar_kmod

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
    <name>custom-wazuh_iris2.py</name>
    <hook_url>/var/ossec/integrations/custom-wazuh_iris2.py</hook_url>  # Path to your script
    <api_key>YOUR_IRIS_DFIR_API_KEY</api_key>  # Replace with your IRIS DFIR API key
    <level>3</level>  # Filter for alerts with severity level 3 or higher (optional)
    <alert_format>json</alert_format>
</integration>

```
Restart the Wazuh agent:
```
service wazuh-agent restart

```

Customization:

When a Wazuh alert is triggered, the script is called with the alert data as a JSON file.
The script extracts relevant information from the alert, including potential IoCs.
An enriched payload containing the alert information and IoCs is constructed.
The script sends a POST request to the IRIS DFIR API to create a new alert.
The script logs the response status code and any errors encountered.
For further details and troubleshooting, refer to the script source code.

Contributing:

We welcome contributions to improve this script. If you have enhancements, please submit a pull request on the script's repository (link to repository).

License:

The script is licensed under the Apache License 2.0 (LICENSE).
