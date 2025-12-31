# cord-rover
`cord-rover` is an e-mail(POP3;IMAP;SMTP) packets analyzer based on Scapy.
## 1. Run:
```bash
sudo python coro.py
```
## 2. We will use telnet to simulate a manual SMTP login to Metasploitable2:
```bash
telnet [META2_IP] 25
# Example: telnet 192.168.204.129 25
```
## 3. Once connected, type the following (the SMTP server will respond to each line):
```bash
HELO test.com                      # To initiate communication with a SMTP server. 
AUTH LOGIN
USER admin
PASS password123
```
## 4. Like this:  
```bash
telnet 192.168.204.129 25
Trying 192.168.204.129...
Connected to 192.168.204.129.
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
HELO test.com
250 metasploitable.localdomain
AUTH LOGIN
USER my_secret
PASS my_pass
```
## 5. The script's output:
```bash
sudo python coro.py
[*] Sniffing... Try typing in your Telnet window now.
[DEBUG] Received data: auth login
[DEBUG] Received data: 503 5.5.1 error: authentication not enabled
[DEBUG] Received data: user my_secret

[!] ALERT: Credentials found!
[*] Destination: 192.168.204.129
[*] Payload: user my_secret
[DEBUG] Received data: 502 5.5.2 error: command not recognized
[DEBUG] Received data: pass my_pass

[!] ALERT: Credentials found!
[*] Destination: 192.168.204.129
[*] Payload: pass my_pass
```

<br>
<br>
**Note**: the BPF filter can be edited to monitor other traffic: for example, to monitor FTP connections and credentials, change it to `tcp port 21` in `coro.py` file. 
