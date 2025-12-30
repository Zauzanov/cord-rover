# cord-rover
`cord-rover` is an e-mail(POP3;IMAP;SMTP) packets analyzer based on Scapy.
## Run:
```bash
sudo python coro.py
```
## Use telnet to test the script:
```bash
telnet
```
<br>
<br>
**Note**: the BPF filter can be edited to monitor other traffic: for example, to monitor FTP connections and credentials, change it to `tcp port 21` in `coro.py` file. 
