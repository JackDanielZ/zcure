# Description

Small library using OpenSSL libraries to establish a secure connection with a secure server.

It uses a certificate to permit the client to verify the identity of the server and public keys to permit the server to identify the client among a list of authorized entities (like authorized_keys.txt)

Generate:
openssl genpkey -out priv.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
openssl pkey -pubout -in priv.pem -out pub.pub
