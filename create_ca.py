import json
import yaml
import sys
with open(sys.argv[1],'r') as f:
    ca = f.read()
with open(sys.argv[2],'r') as f:
    p = yaml.safe_load(f.read())

data = {'private_key':ca,'authdict':p}

url="https://sshauthz.characterisationvl-dev.cloud.edu.au/sshauthz/create"
import json
jsondata = json.dumps(data)
import requests
s = requests.Session()
r = s.post(url=url,json=data)
print(r.status_code)
print(r.text)

