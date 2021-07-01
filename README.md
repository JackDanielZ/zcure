# Description

Small library using OpenSSL libraries to establish a secure connection with a secure server.

It uses ECDH to permit identification of both sides

Generate:
openssl genpkey -out mine.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
openssl pkey -pubout -in mine.pem -out mine.pub

Save mine.pem and mine.pub into ~/.config/zcure/local_key/
Save mine.pub to other machines in ~/.config/zcure/remote_keys/
