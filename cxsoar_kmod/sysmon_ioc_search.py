def search_ioc(alert_json):
 # Extracts IoCs from Sysmon alerts based on relevant fields.

  ioc_lists = []
  ioc_types = {
        
        "sourceIp": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("sourceIp"),
        "sourcePort": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("sourcePort"),
        "destinationIp": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("destinationIp"),
        "destinationPort": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("destinationPort"),
        "hashes": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("hashes"),
        "commandLine": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("commandLine"),
        "queryName": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("queryName"),
        "queryResults": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("queryResults"),
        "queryStatus": lambda alert: alert.get("data", {}).get("win",{}).get("eventdata",{}).get("queryStatus"),


    }
  for ioc_type, extractor in ioc_types.items():
        ioc_value = extractor(alert_json)
        if ioc_value:  # Check if a value was extracted
            ioc_lists.append({
                "ioc_value": ioc_value,
                "ioc_description": f"Extracted from Wazuh alert (type: {ioc_type})",
                "ioc_tlp_id": 1,  # Adjust TLP (Traffic Light Protocol) ID based on your needs
                "ioc_type_id": 2,  # Adjust IoC type ID based on your Iris DFIR configuration
                "ioc_tags": "tag1,tag2",  # Adjust tags as needed
            })

  return ioc_lists