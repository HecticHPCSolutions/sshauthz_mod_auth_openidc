from . import app as app
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--configdir')
parser.add_argument('--subject_header')
parser.add_argument('--clients')
args = parser.parse_args()
app.config['CONFIG']=args.configdir
app.config['SUBJECT_HEADER']=args.subject_header
app.config['CLIENTS_FILE']=args.clients
import logging
logging.basicConfig(filename="sshauthz.log")
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

