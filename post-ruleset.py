import os
import json
import requests
import random
import string
from dotenv import load_dotenv
from argparse import ArgumentParser

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

VTAPI = os.environ.get("VTAPI")

headers = {
   "x-apikey": VTAPI
}

# get arguments
def parser():
    usage = f"python3 {__file__} target_strings"
    description = 'Post livehunt ruleset which hunts specified strings'

    argparser = ArgumentParser(usage=usage, description=description)
    argparser.add_argument('targets', type=open, help='filename includes target strings')
    argparser.add_argument('-n', '--name', type=str, help='rule name')

    args = argparser.parse_args()

    return args

# generate random rule name in case nothing given
def generate_random_string(n):
   return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def post_ruleset(rule_name, targets):
    strings = ""
    condition = ""
    count = 1
    for target in targets:
       strings += f'  $target{count} = "{target}" nocase\n' 
       count += 1

    condition += f'  (any of them)\n'
    condition += f'  and not vt.metadata.file_type == vt.FileType.PE_EXE\n'
    condition += f'  and not vt.metadata.file_type == vt.FileType.PE_DLL\n'
    condition += f'  and not vt.metadata.file_type == vt.FileType.ELF\n'
    condition += f'  and not vt.metadata.file_type == vt.FileType.ANDROID'

    rules = f'import "vt"\n\nrule {rule_name}\n{{\n strings:\n{strings} condition:\n{condition}\n}}'

    # prepare request for VT
    vturl = "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets"

    params = {
        "data": {
            "type": "hunting_ruleset",
            "attributes": {
                "name": rule_name,
                "enabled": True,
                "rules": rules
            }
        }
    }

    response = requests.post(vturl, data=json.dumps(params), headers=headers)
    result = json.loads(response.text)

    print(result)

args = parser()
targets = args.targets.read().splitlines()
rule_name = args.name if args.name else generate_random_string(12)

post_ruleset(rule_name, targets)
