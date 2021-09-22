# Description

Small library using OpenSSL libraries to establish a secure connection with a secure server.

It uses ECDH to permit identification of both sides

# Generate the local key pair:
mkdir -p ~/.config/zcure/local_key/
openssl genpkey -out ~/.config/zcure/local_key/mine.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
openssl pkey -pubout -in ~/.config/zcure/local_key/mine.pem -out ~/.config/zcure/local_key/mine.pub

# Save mine.pub to other machines in ~/.config/zcure/remote_keys/
scp ~/.config/zcure/local_key/mine.pub [remote_machine]:~/.config/zcure/remote_keys/[local_machine]
