This repo runs an OpenID connect to SSH Certificate translation service
It relies on the apache2 mod_auth_oidc component https://github.com/zmartzone/mod_auth_openidc

Familarirty with configuring apache2 and enabling modules on your choice of operatin system is assumed.

This component is simply the wsgi component

Setup:

1. Install a python vevn
2. install uwsgi
3. create clients.yml (i.e. do configuration)
4. use run.sh to excute the uwsgi server
5. configure apache (use oidc.conf as an example)
