# cord-rover
`cord-rover` is an e-mail(POP3;IMAP;SMTP) packets analyzer based on Scapy.
## Run:
```bash
sudo python coro.py
```
## We will use telnet to simulate a manual SMTP login to Metasploitable2:
```bash
telnet [META2_IP] 25
```
## Once connected, type the following (the SMTP server will respond to each line):
```bash
HELO test.com
AUTH LOGIN
USER admin
PASS password123
```
<br>
<br>
**Note**: the BPF filter can be edited to monitor other traffic: for example, to monitor FTP connections and credentials, change it to `tcp port 21` in `coro.py` file. 
