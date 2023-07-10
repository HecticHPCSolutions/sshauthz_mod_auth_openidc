
SERVERFQDN="sshauthz.characterisationvl-dev.cloud.edu.au"

import json
import yaml
import sys
import subprocess
import os

caName = sys.argv[1]
principals = sys.argv[2]
configOut = sys.argv[3]

with open(caName,'r') as f:
    ca = f.read()
with open(principals,'r') as f:
    p = yaml.safe_load(f.read())

data = {'private_key':ca,'authdict':p}

url=f'https://{SERVERFQDN}/sshauthz/create'
import json
jsondata = json.dumps(data)
import requests
s = requests.Session()
r = s.post(url=url,json=data)


fingerprint = ['ssh-keygen', '-l', '-f', sys.argv[1]]
fpprocess = subprocess.Popen(fingerprint, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
(stdout, stderr) = fpprocess.communicate('\n')
fingerPrint=stdout.split(b' ')[1].decode()
import base64
base64FingerPrint = base64.urlsafe_b64encode(fingerPrint.encode()).decode()
name = sys.argv[1]

authdatastr = '''
[ 
  {{ 
    "authorise": "https://{{SERVERFQDN}}/protected/authorize/{base64FingerPrint}", 
    "client_id": "ssossh", 
    "sign": "https://{SERVERFQDN}/sshauthz/sign/{base64FingerPrint}",
    "logout": "https://{SERVERFQDN}/protected/callback?logout=https%3A%2F%2Flocalhost%2F",
    "name": "{caName}",
    "icon": null,
    "scope": "user:email",
    "cafingerprint": "{fingerPrint}",
    "desc": "" 
  }} 
]'''


authdata = authdatastr.format(SERVERFQDN=SERVERFQDN, base64FingerPrint=base64FingerPrint, fingerPrint=fingerPrint, caName=os.path.basename(caName))


with open(configOut,'w') as f:
    f.write(authdata)
