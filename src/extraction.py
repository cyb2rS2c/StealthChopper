import re
import json

def load_tld_mapping(file_path):
    with open(file_path, 'r') as file:
        tld_data = json.load(file)
    tld_to_country = {}
    for entry in tld_data:
        country = entry["country"]
        for tld in entry["tlds"]:
            tld_to_country[tld] = country
    
    return tld_to_country

def extract_base_domain(dns_query, tld_to_country):
    cleaned_query = re.sub(r',+', '.', dns_query)
    cleaned_query = re.sub(r'[^\w\.-]', '', cleaned_query)
    match = re.match(r"(?:[a-zA-Z0-9-]+\.)+([a-zA-Z0-9-]+\.[a-zA-Z]+)", cleaned_query)
    
    if match:
        domain = match.group(1)
        parts = domain.split('.')
        base_domain = '.'.join(parts[-2:])
        tld = '.' + parts[-1]
        country = tld_to_country.get(tld, 'Unknown')
        print(f"Base Domain: {base_domain}, Country: {country}")
        
        return base_domain, country
    else:
        return cleaned_query, 'Unknown'