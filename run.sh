#!/bin/bash
uwsgi \
        --socket 0.0.0.0:8080 \
        --protocol=http \
	--plugins=python3 \
	-H /home/ubuntu/sshauthz/venv \
	--pyargv='--configdir /home/ubuntu/sshauthz --subject_header=Oidc-Claim-Email --clients=clients.yml' \
	-w app.wsgi:app


