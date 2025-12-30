# cord-rover
`cord-rover` is an e-mail(POP3;IMAP;SMTP) packets analyzer based on Scapy.
## Run:
```bash
sudo python coro_no_crash.py
[*] Starting sniffer on email ports...
```
## Demo[!] output for a fictitious account that a mail client allegedly attempted to connect to:
```bash
sudo python coro_no_crash.py
[*] Starting sniffer on email ports...
[*] Destination: 192.168.204.129
[*] b'USER alex\n'
[*] Destination: 192.168.204.129
[*] b'PASS mygreatpassword\n'
```
Here our client is attempting to log in to server 192.168.204.129 and send credentials over the network in plain text.<br>

<br>
<br>

**Note 1**: the BPF filter can be edited to monitor other traffic: for example, to monitor FTP connections and credentials, change it to `tcp port 21` in `coro.py` file. <br>
<br>
<br>
**Note 2**: `coro_initial.py` file's crashing reason: if a packet arrives without a payload (like a standard TCP ACK), the variable `mypacket` will not be defined, causing the script to crash with an `UnboundLocalError`.
