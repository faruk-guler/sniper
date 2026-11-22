# the sniper eBPF deep monitoring tool

## Log Read

```powershell
tail -f outbound-dump.log
grep curl outbound-dump.log
grep ":443" outbound-dump.log
sort outbound-dump.log | awk '{print $4}' | sort | uniq -c | sort -rn | head
```
## Alternative log path

```powershell
sudo python3 sniper.py --log-dir /yol
```
