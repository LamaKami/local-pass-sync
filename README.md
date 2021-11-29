# local-pass-sync
This solution is for everyone who wants to keep there keepass file only on your devices.
It uses https for the server-client communication and ed25519 keys for the authorization.
You also could also use a server outside your network.

## What does the program do? <br>
Suppose you have a keepass file on two or more different devices and you don't want to synchronize them on an external server but only locally. If you now change both files outside your network and come back, you can synchronize both files with your local server. The program takes the latest change of a keepass entry and sends the new file back to you and saves it locally again.
<br>
In short, the server has a file and compares it with the incoming file, updates the server file and sends the updated file back.

### Advantage: <br>
You can change multiple files on your devices and don't have to manually compare your keepass entries.

### Limitations (TODOs):
* no support for groups (if you use them) in keepass
    * it writes all new entries in the root directory
* no deletion for entries
    * until it is supported you can use a workaround (see below)
* no support for files in entries
* only supports Keepass 2 files (v2.30 kdbx or higher)

### Requirements:
* Server (e.g. Raspberry Pi)
    * you could also try this on only one pc
* Golang on server and clients
    * run `go build` in the repository to get all the missing packages

### Authentication preparations:
1. https (only need to do this once)
    1. `go run /usr/local/go/src/crypto/tls/generate_cert.go -host [server_ip]`
    2. -host: `localhost` only if you want to try it on only one device, else choose the ip from the server in your local network like `196.168.0.2`
    3. `go run /usr/local/go/src/crypto/tls/generate_cert.go -help` for more information
    4. Note: the certificate is 365 days valid if you don't change the duration with `-duration 0h1m0s` where the certificate would now be 1 minute valid
    5. The `cert.pem` has to be placed on the server and the clients
    6. The `key.pem` file has to be placed only on the server
    7. Then you have to update your `config.yaml` on server and clients
2. Create SSH-Key if you don't have an ed25519 ssh-key on the clients (you should do this on each client)
    1. `ssh-keygen -t ed25519-sk -C "your_email@example.com"`
    2. Add the path from your ed25519-private-key in the `config.yaml` (ed25519private/path)
    3. Get public key in required format for the server: `go run main.go pubKey`
    4. copy the output and place it in the `authorized_keys` file, which should be placed on the server

### Example for authorized_keys
After you created both private keys (e.g. you have two clients) and extracted the public keys and inserted them in the file on the server, the file should look something like this:
```
-----BEGIN PUBLIC KEY-----
SMKDSDGDAg643fdksadklasndskl6454AFASSFGFV342SADKNnkk/j2C4HA=
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
SAKJNGIENLKLNSCklJksndggadkdfsdfsdkasld567JSJFdgsdfe/IF7Aib=
-----END PUBLIC KEY-----
```

### Config-File
The `config.yaml` file is very important for the program to work. You need to customize the file on each pc. The file is documented on its own, but if you are unsure, do not hesitate to ask questions.


### Calls
* Get:
    * `go run main.go getFile` downloads the keepass file from the server and replaces it with the local file
* Patch:
    * `go run main.go compareFiles` sends the local keepass file to the server and updates the server file. It also updates the local file.
* Put:
    * `go run main.go replaceFile` sends the local keepass file and replaces it as the new server file

### Deletion workaround
1. Put with the most recent file (replaces server file with local file)
2. Get on all others devices (replaces local file with server file)

### Good to know:
* It takes some time on a raspberry to unlock and lock the files. On a Pi 4 it takes xx seconds to update the file.

### Additional TODOs
* File history on the server for each client


## Acknowledgment:<br>
For changing the keepass files I'm using the code from Tobias Schoknecht
https://github.com/tobischo/gokeepasslib
