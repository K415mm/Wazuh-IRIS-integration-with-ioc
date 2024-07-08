def search_ioc(alert_json):
  """
  Extracts IoCs from Sysmon alerts based on relevant fields.

  Args:
      alert_json (dict): A dictionary containing the Wazuh alert data.

  Returns:
      list: A list of dictionaries representing extracted IoCs.
  """

  ioc_lists = []
  # Implement logic to extract IoCs from Sysmon alert data
  # Here are some potential fields to check:
  # - 'process']['command'] (for process name)
  # - 'process']['args'] (for process arguments)
  # - 'file']['name'] (for file name)
  # - 'network']['source_ip'] (for source IP address)
  # - 'network']['destination_ip'] (for destination IP address)
  # - 'network']['domain'] (for domain name)
  # ... (add more fields as needed)

  # Example: Extract process name as IoC
  
  eventdata = alert_json.get('data', {}).get('eventdata', {})
  sourceIp = eventdata.get('sourceIp', None)
  if sourceIp:
    ioc_lists.append({
      "ioc_value": sourceIp,
      "ioc_description": "Extracted sourceIp from Sysmon alert",
      "ioc_tlp_id": 1,  # Adjust TLP (Traffic Light Protocol) ID based on your needs
      "ioc_type_id": 2,  # Adjust IoC type ID based on your Iris DFIR configuration
      "ioc_tags": "tag1,tag2",  # Adjust tags as needed
      # ... other IoC details (TLP ID, type ID, tags)
    })

  # Add logic to extract other IoCs from relevant Sysmon alert fields

  return ioc_lists
