#!/bin/bash

openssl ecparam -name prime256v1 -genkey -out key.pem
# openssl genpkey -out key.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256

openssl req -new -x509 -key key.pem -out cert.pem -days 365 -config cert.conf

