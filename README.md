# Secure-Transfer
Transferring files from client to server with encryption and authentication features built-in.

## Security Features
The security features it implements include:
- RSA Encryption of session key with client's public key
- AES Encryption (EAX Mode) for the remainder of messages with session key
- Username and Password authentication (Password uses SHA512)
- SHA256 File Checksum

## Project Files
- scp_server.py
- scp_client.py

## Running the Program
1. Run scp_server.py first without arguments:
    python scp_server.py
2. Run scp_client.py second with arguments:
    python scp_client.py [USERNAME] [PASSWORD] [FILENAME]

### Available User & Passwords:
- "user" , "password"
- "kit"  , "cischke"
- "test" , "test"

### Included Test files:
- picture.jpg
- script.txt
