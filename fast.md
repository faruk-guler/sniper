# fast sniper commands

# Linux
```powershell
watch ss -tulpan # canlı TCP/UDP bağlantıları ve dinleyen portlar
sudo tcpdump -i any 'icmp or icmp6' # canlı ping izle gelen-giden
execsnoop-bpfcc # yeni süreçleri canlı izle
```

```powershell
bpftrace -e '
kprobe:vfs_write
/comm != "bpftrace" && comm != "sshd"/
{
    $file = (struct file *)arg0;
    $name = str($file->f_path.dentry->d_name.name);

    if ($name != "") {
        printf("%s WRITE pid=%-6d uid=%-5d comm=%-16s bytes=%d file=%s\n",
            strftime("%H:%M:%S", nsecs),
            pid, uid, comm, arg2, $name);
    }
}'
```
