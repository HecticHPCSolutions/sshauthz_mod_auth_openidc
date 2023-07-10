# sshauthz_mod_auth_oidc

- This code generates SSH certificates. For more info on what they are take a look in the docs directory
- This is a wsgi program. It needs to run inside a wsgi executor like uwsgi or gunicorn.
- This program needs a request header to be set. Usually I configure this behind an apache server with `mod_auth_oidc`
`mod_auth_oidc` sets a header called Oidc-Claim-Email. The runtime argument `--subject_header=Oidc-Claim-Email` Informs the code that we want to use that header (you could instead use the REMOTE_USER header if you wish)


## How to give it a try

1. Clone this repo
1. Also clone https://github.com/HecticHPCSolutions/ssossh
1. Generate a CA with a command line `ssh-keygen -t ed25519 -f ca` .... Don't set a passphrase here
1. Generate a principals.yml file with content like. This file must include the username you want to use. it may include a list of usernames as shown
```
max_expiry: 86400
chris.hines@monash.edu:
  principals:
    - rocky
    - ubuntu
    - centos
    - ec2-user
    - debian
```
(Note, my demo server is using Google IdP. If your employer has signed you up for google apps you should be golden, otherwise use your personal gmail)
1. run `python3 ./sshauthz_mod_auth_openidc/create_ca.py ./ca ./principals.yml ssossh_conf.json`
1. run `PYTHONPATH=./ssossh python3 -m ssossh -c ./ssossh_conf.json`
1. cat ca.pub ... copy the content to clipboard
1. Choose a SSH server that you already have access to. Paste the clipboard content into ~/.ssh/authorized_keys
1. Prepend the pasted line with `cert-authority` so it looks like this
```
chines@tun:~$ cat ~/.ssh/authorized_keys | grep cert-authority
cert-authority ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNXYe7NQ2g3vldeMtRq+axkx7oRmJR4wbhjmU0f5TClN/GvumpxgezQ5lhS699HFIjbHSUcKYh8oVS8QfJPFG9jArgKRk+lFFO+xlm7tORIS36oTvNx0UrOpRfKUZVRd+EUd3m5r0Yq1uGgCOC3bNoaBLiQrnWUaRdaul6Y9ZKP2rSKo1e7udxTGAKl/fxF4q31NllPEG5k62psG17XuqjyImrI1pxBr0fpcyWmYyYRmqQQ2srox0Npw6T3yrcROSbVCz6htlAKuIEILe8lXSwUCADmRUMqNNkMryXi21u0KdKeganiY+u+Q+Rnt7jD8pvBlkC58w7QGn6+wakSGNp chines@mash
chines@tun:~$
```
1. ssh <username>@<sshhost> -o IdentityAgent=/dev/null -o IdentityFile=~/.ssh/ca

You can get as smart as you want with the IdentityFile and the agent. The ssossh script has a number of options including editing your .ssh/config or loading the key into an agent rather than saving to a file.

## How to be just a little bit smarter

1. Don't use my demo server in prod. The admins on that server can use your CA key to impersonate you. You shouldn't trust me.
1. Contents in authorized_keys can be set by cloud-init process on OpenStack, AWS or MaaS (maybe GCP and Azure but I haven't tried) However OpenStack won't allow you to put the cert-authority in there. I have to use a user data script to add in the cert-auhtority part with sed.
1. If you want to enable this for all users on the ssh server, you edit the sshd_config (usually /etc/sshd/sshd_config) and set the Option TrustedUserCAKeys to a file containing the public key
1. The max expiry sets how long a cert will work for. I don't have a solution for key revocation yet. 24 hours seems a good balance between convenience and automatic revoking an old key. But make your own decisions.
1. Once you've got your users comfortable with requesting and using certs, the next phase is to disable passwords in ssh and disable users authorized_keys (Authorized_keysFile=none in sshd_config)

## How to run your own server

1. Create an instance
1. Configure apache and SSL certs
1. Obtain OpenID Connect client credentials. 
    - you will need your callback or redirect  URL which is  by default `https://{{FQDN}}/protected/callback`
    - If you have google apps, its easy to get a google IdP (see docs/overview.md for details)
    - You can also go diredtly to IdPs like Okta
    - You can also ask AAF for an OIDC client. This will connect you to the existing Shibboleth federation
1. Edit the app to set ALLOWCREATE=True
1. Run the app in a wsgi server (edit the run.sh file)
1. Configure the reverse proxy (use oidc.conf as an example)
    - You will need the OpenID Connect credentials here
1. Create a principals file according to the template
1. Generate an ssh key (`ssh-keygen -t ed25519 ca`)
1. Upload the key and principals file to the app using the create_ca.py script
1. Edit the app to set ALLOWCREATE=False
1. Restart the app

If you want you can create princiapls files and ca keys directly without using the create_ca.py script
To do you you will want to fingerprint the private key and convert to base64. Look in the create_ca.py script for tips on how to do this.
In "prod" you will want a way to generate the principals file automatically from your list of users (maybe by querying ldap?)

## Security Considerations

create_ca.py is intended to be used for testing/demo purposes. It calls an endpoint called /create (this is disabled in code, but enabled on my demo server)

TODO: It might be a good idea to store the ca files encypted with a passphrase, and require that passphrase on boot.

## Other notes

This server effectively implements OAuth2 Implicit flow, however its abusing the JWT as the bearer token. As a general principal the bearer token should be opaque, so this isn't so great.

Also this server only does Implicit flow. I do have one that does code flow as well (https://gitlab.erc.monash.edu.au/hpc-team/pysshauthz)
