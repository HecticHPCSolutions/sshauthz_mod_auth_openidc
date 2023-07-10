from flask import Flask, request, abort, redirect
from flask_restful import Api, Resource
import logging
logger = logging.getLogger()
ALLOWCREATE=False

def get_fingerprint(data):
    # Given SSH Public key data, generate its fingerprint
    import tempfile
    import os
    import subprocess
    import traceback
    keyfile = tempfile.NamedTemporaryFile(delete=False,mode='w+b')
    fp = None
    if type(data) == str:
        key = data.encode('utf-8')
    if type(data) == bytes:
        key = data
    try:
        keyfile.write(key)
        keyfile.close()
        fingerprint = ['ssh-keygen', '-l', '-f', keyfile.name]
        fpprocess = subprocess.Popen(fingerprint, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = fpprocess.communicate('\n')
        os.unlink(keyfile.name)
        fp = stdout.split(b' ')[1]
        return fp.decode()
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        os.unlink(keyfile.name)
        return None

def get_fingerprint_base64(data):
    # given ssh private key data, generate a fingerprint and base64 encode it ... this leads to a string which is useful for filenames
    import base64
    fp = get_fingerprint(data)
    return base64.urlsafe_b64encode(fp.encode()).decode()



def sign_cert(principals, pubkey, period, ca):
    # given a public key and a list of users that key should work for, generate an apprporaite certificate
    # also logs the command used for all signing so we have a record of who was issued a cert when for audit
    import subprocess
    import tempfile
    import os
    import logging
    logger = logging.getLogger('signinglog')
    keyid = get_fingerprint_base64(pubkey)
    pubkeyfile = tempfile.NamedTemporaryFile(delete=False, suffix='.pub', mode='w+b')
    pubkeyfile.write(pubkey.encode('utf-8'))
    pubkeyfile.close()
    sign = ['ssh-keygen', '-s', ca, '-I', keyid, '-n', ','.join(set(principals)), 
            '-V', "+{}s".format(str(int(period))), pubkeyfile.name]
    logger.info(sign)
    signprocess = subprocess.Popen(sign, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stderr, stdout) = signprocess.communicate()
    certfilename=pubkeyfile.name[:-4]+"-cert.pub"
    with open(certfilename) as certfile:
        cert = certfile.read()
    os.unlink(certfilename)
    os.unlink(pubkeyfile.name)
    return cert

def get_cert_options(ca, subject):
    # Helper function: given the user logging in, what options should be applied to their certificate eg 
    # expiry date usernames etc.
    # TODO: Support a force_command option ... This would be needed to lock down "secure" clusters were data egress must be approved by a data custodian.
    import os
    import yaml
    import datetime
    optionsfile = os.path.join(app.config['CONFIG'],'{}.yml'.format(ca))
    with open(optionsfile,'r') as f:
        try:
            cadata = yaml.safe_load(f.read())
            data = cadata[subject]
            data['ca'] = ca
            if not 'max_expiry' in data:
                if 'max_expiry' in cadata:
                    data['max_expiry'] = cadata['max_expiry']
                else:
                    data['max_expiry'] = int(datetime.timedelta(days=1).total_seconds())
            if not 'mail' in data:
                data['mail'] = subject
            return data
        except KeyError:
            abort(401,{'message':'{} does not have an account'.format(subject)})

class Authorize(Resource):
    # Authorisation endpoint. This doesn't generate the certificate, but forces the user to login with OIDC, and passes the token back to the user program/agent eg ssossh, strudel2
    def get(self, ca):
        sub = request.headers.get(app.config['SUBJECT_HEADER'])
        if sub is None:
            abort(401,{'message':'no subject provided {} {}'.format(app.config['SUBJECT_HEADER'],dict(request.headers))})
        args = request.args
        if args.get('response_type')!='token':
            abort(500)
        try:
            import yaml
            redirect_url = args.get('redirect_uri')
            client = args.get('client_id')
            with open(app.config['CLIENTS_FILE'],'r') as f:
                clients = yaml.safe_load(f.read())
                if not redirect_url in clients[client]:
                    abort(401)
        except Exception as e:
            import traceback
            logger.error('failure in authorising client {}'.format(client))
            abort(401,{'message': 'no matching client/redirect'})
        state = args.get('state')
        cert_options = get_cert_options(ca, sub)
        import datetime
        import pytz
        exp = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)+datetime.timedelta(minutes=1)
        import jwt
        token=jwt.encode({'data':cert_options,'exp':exp},app.config['SECRET'],algorithm='HS256')
        url=redirect_url+"#access_token={}&token_type=bearer".format(token)
        if state is not None:
            url = url+"&state={}".format(state)
        return redirect(url,302)

class Create(Resource):
    # Create endpoint. Allows a user to setup a new CA. For example if they want to use strudel2 on their own VM
    # Also allows you to update the list of emails -> usernames via HTTP rather than logging in
    # this doesn't require authentication.
    def post(self):
        import yaml
        data = request.get_json(force=True)
        logger = logging.getLogger()
        logger.debug(data)
        if not 'private_key' in data and 'authdict' in data:
            abort(400,{'message': 'incorrect data format'})
        key = data['private_key']
        authdict = data['authdict']
        keyid = get_fingerprint_base64(key)
        if keyid is None:
            abort(400,{'message': 'invalid private key'})
        keyname = os.path.join(app.config['CONFIG'],keyid)
        oldumask = os.umask(0o077)
        with open(keyname,'w+b') as f:
            f.write(key.encode('utf-8'))
        with open(keyname+".yml",'w+') as f:
            f.write(yaml.dump(authdict))
        os.umask(oldumask)

class Sign(Resource):
    # Generate a certificate. This ss an OAuth2 Implicit Protected Resource (so OIDC is all done by this point)
    def post(self, ca):
        import jwt
        import flask
        import dateutil.parser
        import datetime
        import pytz
        cafile = os.path.join(app.config['CONFIG'],ca)
        if not os.path.isfile(cafile):
            abort(500,{'message':'no file corresponding to ca {}'.format(ca)})
        token=request.headers.get('Authorization').split(' ')[1]
        cert_options = jwt.decode(token, app.config['SECRET'],algorithms=['HS256'])['data']
        if cert_options['ca'] != ca:
            abort(401, {'message': 'something fishy is happening'})
        data = request.get_json(force=True)
        pubkey = data['public_key']
        if 'end' in data:
            try:
                utcnow=datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
                period=min((dateutil.parser.parse(data['end'])-utcnow).total_seconds(), cert_options['max_expiry'])
            except:
                logger.debug("invalid end time for certificate signing (couldn't be parsed by dateutil.parser.parse)")
                abort(500,{'message':"invalid end time for certificate signing (couldn't be parsed by dateutil.parser.parse)"})
        else:
            period=cert_options['max_expiry']
        cert=sign_cert(cert_options['principals'],pubkey,period,cafile)
        return flask.jsonify({'certificate': cert,'user':",".join(cert_options['principals']),'mail':cert_options['mail']})


app = Flask(__name__)
import os
key=os.urandom(24)
app.config['SECRET']=key
api = Api(app)
if ALLOWCREATE:
    api.add_resource(Create,'/create')
api.add_resource(Authorize,'/authorize/<string:ca>')
api.add_resource(Sign,'/sign/<string:ca>')
