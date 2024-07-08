def search_ioc(alert_json):
  

    ioc_lists = []
    ioc_types = {
        "md5": lambda alert: alert.get("syscheck", {}).get("md5_after"),
        "sha1": lambda alert: alert.get("syscheck", {}).get("sha1_after"),
        "ipv4": lambda alert: alert.get("data", {}).get("srcip"),
        "hostname": lambda alert: alert.get("data", {}).get("hostname"),
        "url": lambda alert: alert.get("data", {}).get("url"),
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