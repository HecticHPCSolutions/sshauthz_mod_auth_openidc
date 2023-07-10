# sshauthz_mod_auth_oidc

- This code generates SSH certificates. For more info on what they are take a look in the docs directory
- This is a wsgi program. It needs to run inside a wsgi executor like uwsgi or gunicorn.
- This program needs a request header to be set. Usually I configure this behind an apache server with `mod_auth_oidc`
`mod_auth_oidc` sets a header called Oidc-Claim-Email. The runtime argument `--subject_header=Oidc-Claim-Email` Informs the code that we want to use that header (you could instead use the REMOTE_USER header if you wish)

## Howto use this code

1. Create an instance
1. Configure apache and SSL certs
1. Edit the app to set ALLOWCREATE=True
1. Run the app in a wsgi server (edit the run.sh file)
1. Configure the reverse proxy (use oidc.conf as an example)
1. Create a principals file according to the template
1. Generate an ssh key (`ssh-keygen -t ed25519 ca`)
1. Upload the key and principals file to the app using the create_ca.py script
1. Edit the app to set ALLOWCREATE=False
1. Restart the app

## Security Considerations

create_ca.py is intended to be used for testing/demo purposes. It calls an endpoint called /create (this is commented out in code, but uncommented on my demo server)

