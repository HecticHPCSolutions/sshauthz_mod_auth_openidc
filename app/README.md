SSOSSH - what is is good for
============================

Most web services are moving to single sign on (eg log in with google etc) with good reason: its simpler for the user, there are less passwords to remember. There is less security framework for the service developer to create. You get MFA for free when you use an IdP that already done MFA. We want the same for our SSH connections

The key to this is SSH certificates. A certificate is much like a public key, but, instead of being placed in the users authorized_keys file, its signed by a certificate authority. The certificate authority adds dates during which the cert is valid, and indicates (again through public key crypto) who the CA was that signed the cert. The CA can be configured for either all users on a computer (through the global sshd_config file) or for an individual user (through their authorized_keys file)

The idea is to:
a) create a web service that wraps the certificate authority so that users can use SSO to authenticate and mint a new certificate automatically
b) set the validity period to be something short so that users are required to repeat SSO regularly (say once a week) so that offboarding is simpler (we just want for their certs to expire)

This idea is well proved and implemented commercially, and in somecases by community editition by (at least)
Teleport (goteleport.com)
SmallStep CA (smallsetp.com)
HasiCorp Vault (https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)

We are already usign this technology to underpin Strudel-web and Strudel2 services, however, because we settled on ssh certs before any of these offerings were available, we wrote out own.


Feature Wishlist
================

OpenID Connect for Authentication: This seems like a no brainer. Its the defacto for web services. AAF supports it
OAuth2 for Authorization: Again OAuth2 is the defacto, but for browser based clients and non-browser clients (like using ssh in the terminal). If you've ever coded with teh python API for google sheets you will know what this looks like. You run the script, a browser window opens and asks you to login in. You say OK, and the window says "you can close the window now" and then your script works.
User defined CAs: Strudel2 allows web based access to any linux ssh enabled computer. You only need to configure the SSH Certificate Authority. If a user can easily say "This is my research groups computer and these people should be able to login and run JupyterLab on it" it may be really helpful.



