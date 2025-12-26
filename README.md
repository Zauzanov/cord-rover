# cord-rover
cord-rover is a packet analyzer based on Scapy. 

## 1. Run:
```bash
sudo python coro.py
```
## 2. Output looks like this:
```bash
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:0c:29:43:51:7c
  type      = IPv4
###[ IP ]### 
     version   = 4
     proto     = tcp
     src       = 192.168.1.10
     dst       = 192.168.1.1
... (and so on)

```
