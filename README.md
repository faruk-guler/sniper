# The Sniper of eBPF deep monitoring tool
<img src="intro/sniper-intro.PNG" alt="INTRO" width="600" height="1000">

- Name Sniper
- Author: faruk-guler
- Version: 0.2

## Requirements
```powershell
Debian:
sudo apt update
sudo apt install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

RHEL:
sudo dnf update
sudo dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r)
```

## Usage
```powershell
sudo python3 sniper.py
sudo python3 sniper.py --log-dir /dir
sudo python3 sniper.py --format json
sudo python3 sniper.py --no-cmd
```

## Log Read
```powershell
tail -f outbound-dump.log
tail -f inbound-dump.log
grep curl outbound-dump.log
grep ":443" outbound-dump.log
sort outbound-dump.log | awk '{print $4}' | sort | uniq -c | sort -rn | head
```

## Features
- Giden TCP bağlantılarını izleme (Outbound Monitoring).
- Gelen TCP bağlantılarını izleme (Inbound Monitoring).
- IPv4 bağlantılarını izleme.
- IPv6 bağlantılarını izleme.
- TCP bağlantı başlangıcını takip etme.
- TCP bağlantı kabul işlemlerini takip etme.
- Yerel IP adresini tespit etme.
- Uzak IP adresini tespit etme.
- Yerel port bilgisini kaydetme.
- Uzak port bilgisini kaydetme.
- Bağlantının yönünü belirleme.
- Bağlantı zaman damgasını kaydetme.
- Yerel ve uzak adresleri ayrı ayrı gösterme.
- Bağlantıyı oluşturan PID bilgisini kaydetme.
- Process adını kaydetme.
- Linux kullanıcı adını tespit etme.
- UID bilgisini kaydetme.
- Process komut satırını /proc/PID/cmdline üzerinden okuma.
- Process bilgilerini ağ bağlantılarıyla ilişkilendirme.
- Gelen bağlantıyı kabul eden yerel sürecin bilgilerini kaydetme.
- DNS üzerinden hostname tahmini.
- getaddrinfo() fonksiyonunu izleme.
- OpenSSL SNI bilgisini yakalama.
- SSL_set_tlsext_host_name() fonksiyonunu izleme.
- Hostname bilgisini ilgili PID ile eşleştirme.
- DNS kaynaklı hostname bilgisini belirtme.
- SNI kaynaklı hostname bilgisini belirtme.
- Hostname cache sistemi.
- 20 saniyelik hostname cache süresi.
- Eski cache kayıtlarını temizleme.
- Hostname bilgisini giden bağlantı kayıtlarına ekleme.
- --no-host ile hostname analizini kapatma.
