How this version differs from the original: I set it up with iPhone7 / iOS 15.8.4 and Elementary OS 7.1, changing parts where setup and progress differs from the original one. 

Last full system setup: May of 2025

---

# iOS Penetration Testing Cheat Sheet

Everything was tested on Elementary OS 7.1 Horus (64-bit) and iPhone 7 with iOS v15.8.4 using palera1n rootful jailbreak (checkm8 exploit).

If you didn't already, read [OWAS MASTG](https://mas.owasp.org/MASTG/) \([GitHub](https://github.com/OWASP/owasp-mastg)\) and [OWASP MASVS](https://mas.owasp.org/MASVS/) \([GitHub](https://github.com/OWASP/owasp-masvs)\). You can download OWASP MASTG checklist from [here](https://github.com/OWASP/owasp-mastg/releases).

I also recommend reading [Hacking iOS Applications](https://web.securityinnovation.com/hubfs/iOS%20Hacking%20Guide.pdf) and [HackTricks - iOS Pentesting](https://book.hacktricks.xyz/mobile-apps-pentesting/ios-pentesting).

__In most cases, to be eligible for a bug bounty reward, you need to exploit a vulnerability with non-root privileges, possibly building your own "malicious" app.__

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [first.org/cvss/calculator/4.0](https://www.first.org/cvss/calculator/4.0)
* [nvd.nist.gov/vuln-metrics/cvss/v3-calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

## Table of Contents

**0. [Install Tools](#0-install-tools)**

* [Jailbreaking an iOS Device](#jailbreaking-an-ios-device)
* [Sileo Sources and Tools](#sileo-sources-and-tools)
* [Linux Tools](#linux-tools)
* [Mobile Security Framework (MobSF)](#mobile-security-framework-mobsf)

**1. [Basics](#1-basics)**

* [Install/Uninstall an IPA](#installuninstall-an-ipa)
* [SSH to Your iOS Device](#ssh-to-your-ios-device)
* [Download/Upload Files and Directories](#downloadupload-files-and-directories)

**2. [Inspect an IPA](#2-inspect-an-ipa)**

* [Pull a Decrypted IPA](#pull-a-decrypted-ipa)
* [Binary](#binary)
* [Info.plist](#infoplist)
* [AnyTrans](#anytrans)

**3. [Search for Files and Directories](#3-search-for-files-and-directories)**

* [NSUserDefaults](#nsuserdefaults)
* [Cache.db](#cachedb)

**4. [Inspect Files](#4-inspect-files)**

* [Single File](#single-file)
* [Multiple Files](#multiple-files)
* [File Scraper](#file-scraper)
* [SQLite 3](#sqlite-3)
* [Property Lister](#property-lister)
* [Nuclei](#nuclei)
* [Backups](#backups)

**5. [Deeplinks](#5-deeplinks)**

**6. [Frida](#6-frida)**

* [Frida Scripts](#frida-scripts)

**7. [Objection](#7-objection)**

* [Bypasses](#bypasses)

**8. [Repackage an IPA](#8-repackage-an-ipa)**

**9. [Miscellaneous](#9-miscellaneous)**

* [Monitor the System Log](#monitor-the-system-log)
* [Monitor File Changes](#monitor-file-changes)
* [Dump the Pasteboard](#dump-the-pasteboard)
* [Get the Provisioning Profile](#get-the-provisioning-profile)

**10. [Tips and Security Best Practices](#10-tips-and-security-best-practices)**

**11. [Useful Websites and Tools](#11-useful-websites-and-tools)**

## 0. Install Tools

---

### **Jailbreaking an iOS Device (Palera1n Method)**

**⚠️ Warning:** Jailbreaking your iOS device will void its warranty. I am not responsible for any damage or consequences that result from following this guide. Proceed at your own risk.

You can jailbreak your iPhone using [palera1n](https://palera.in), a semi-tethered jailbreak for checkm8-vulnerable devices like the **iPhone 7 running iOS 15.8.4**.

---

#### ✅ **What You’ll Need**

* A Mac or Linux computer
* A Lightning-to-USB cable (preferably original or MFi-certified)
* iPhone 7 or 7 Plus on iOS **15.0 – 15.8.4**
* Terminal access (with root/sudo permissions)

---

#### **1. Initial Setup (First Run)**

```bash
sudo palera1n -c -f -V  # CREATE FAKEFS
```

**Expected Steps:**

1. Enters recovery → DFU mode (follow on-screen prompts)
2. Displays PongoOS screen
3. Creates fakeFS (takes about 5–10 minutes)
4. Device reboots into recovery mode (shows iTunes logo)

#### **2. Final Jailbreak (Second Run)**

```bash
sudo palera1n -f -V  # SKIP FAKEFS CREATION
```

**Observation:**

* If the process stalls at “Booting Kernel...,” the exploit is working but bootloader communication fails.

#### **3. Kernel Boot Troubleshooting**

If stuck at “Booting Kernel...”:

1. **Force Restart the iPhone** (Hold Power + Volume Down)
2. **Manually Re-enter DFU Mode:**

   * Hold Power + Volume Down for 3 seconds
   * Release Power, continue holding Volume Down for 7 seconds
3. Run the recovery command:

```bash
sudo palera1n -f -R -V  # FORCE RECOVERY MODE
```

#### **4. Post-Jailbreak Verification**

If successful:

1. iPhone reboots to the **home screen**
2. **Palera1n loader app** appears (may take up to 2 minutes)
3. Open the loader app → Install **Sileo**

---

#### 🛠️ **Still Stuck on “Booting Kernel...” After 10 Minutes?**

1. **Check USB Power State:**

```bash
cat /sys/bus/usb/devices/1-4/power/runtime_status
```

* Should return `active`

2. **Try Alternate Boot Mode:**

```bash
sudo palera1n -f -B tw1n -V
```

3. **As a Last Resort:**

```bash
sudo palera1n --force-revert -V
```

---

#### 📌 Key Notes

* Use the `-c` flag **only on the first run**
* On subsequent runs, use `-f`
* If the kernel fails to boot, try a different USB port or cable
* Your logs confirm the exploit is functional—this is purely a bootloader/USB issue

---

#### ✅ After Jailbreak

* Open the **Palera1n Loader**
* Tap **Install Sileo**
* Begin installing tools and tweaks
---

### Sileo/Zebra Sources and Tools

Add the following sources to Sileo or Zebra (both work):
* [BigBoss] (http://apt.thebigboss.org/repofiles/cydia/dists/stable/main/binary-iphoneos-arm/)
* [AppSyncUnefied.deb] (https://github.com/akemin-dayo/AppSync/releases/tag/116.0)
* [Merona] (https://repo.co.kr)
* [ElleKit] (https://ellekit.space)
* [Frida](https://build.frida.re)
* [Havoc](https://havoc.app)
* [jjolano](https://ios.jjolano.me)

Install required tools on your iOS device using Sileo/Zebra:

* libAPToast (BigBoss) **pre-requisite for the rest**
* Filza (BigBoss) **pre-requisite for AppSync Unefied**
* A-Bypass (Merona)
* AppSync Unified (Github deb package. Download directly, open with Filza and click Install)
* ElleKit (ElleKit)
* Frida (Frida)
* ReProvision Reborn (Havoc)
* Shadow (jjolano) **replacement for iOS 13 SSL Kill Switch, will see if it works/to be tested**
* PreferenceLoader (palera1n)
* Cycript (palera1n strap)
* nano (palera1n strap)
* dpkg (palera1n strap)
* SQLite 3.x (palera1n strap)
* wget (palera1n strap)
* zip (palera1n strap)
* openssh (palera1n strap)

Over time, some apps might start throwing errors due to the new updates, if reinstalling them does not solve the issues, then try to uninstall them completely and install them again.


### SSH to Your iOS Device

#### **1. Find Your iPhone’s IP Address**
- **On iPhone:**  
  - Go to **Settings → Wi-Fi** → Tap the **ⓘ icon** next to your network.  
  - Your local IP (e.g., `192.168.0.248`) is listed under **IP Address**.

---

#### **2. Connect via SSH**

##### **Default Credentials**  
```bash
ssh root@[IP_ADDRESS]  # e.g., ssh root@192.168.0.248
```
- **Password:** `alpine`

##### **If `alpine` Doesn’t Work**  
1. Log in as `mobile` (uses the same password by default):  
   ```bash
   ssh mobile@[IP_ADDRESS]
   ```
2. Once logged in, reset the `root` password:  
   ```bash
   passwd root
   ```
   - *No old password needed if logged in as `mobile`!*  
   - Set a new password and confirm.  

3. Retry SSH as `root` with the new password.  

### Linux Tools

Install required tools on your Linux:

```bash
sudo apt-get -y install docker.io

sudo systemctl start docker

sudo add-apt-repository universe
sudo apt-get update

sudo apt-get -y install ideviceinstaller libimobiledevice-utils libplist-utils sqlite3 sqlitebrowser xmlstarlet

sudo snap install radare2 --classic

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

pip3 install frida-tools objection property-lister file-scraper
```

More information about my tools can be found at [ivan-sincek/property-lister](https://github.com/ivan-sincek/property-lister) and [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

Make sure that Frida and Objection are always up to date:

```fundamental
pip3 install --upgrade frida-tools objection
```

### Mobile Security Framework (MobSF)

Install:

```fundamental
docker pull opensecurity/mobile-security-framework-mobsf
```

Run:

```fundamental
docker run -it --rm --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

Navigate to `http://localhost:8000` using your preferred web browser.

Uninstall:

```fundamental
docker image rm opensecurity/mobile-security-framework-mobsf
```

### MacOS System

#### **📹 Reference**

Based on setup from:  
[YouTube: macOS Virtual Machine Guide](https://www.youtube.com/watch?v=Qa6y_CiyAMA&t=463s)

#### **1. Install Quickemu**

```bash
sudo apt-add-repository ppa:flexiondotorg/quickemu
sudo apt update
sudo apt install quickemu
```

#### **2. Download macOS Image**

```bash
quickget macos catalina  # For macOS Catalina
# Alternative versions available: big-sur, monterey, ventura
```

#### **3. Start the VM**

```bash
quickemu --vm macos-catalina.conf
```

---

#### **4. macOS Installation Process**

1. **Boot Menu Options:**
   - Select `macOS Base System`
   
2. **Disk Setup:**
   - Select `Disk Utility`
   - Erase disk and name partition (e.g., `macos`)
   - Close Disk Utility

3. **OS Installation:**
   - Select `Reinstall macOS ${YourDistro}`
   - Follow installer prompts until you see your named partition
   - Select your partition (`macos`) to complete installation

4. **Initial Setup:**
   - Complete macOS first-run configuration
   - enable trimforce so data won't pile up
```bash
sudo trimforce enable
```

---

### **⚙️ Recommended VM Configuration**

Edit the generated `.conf` file for better performance:

```conf
#!/usr/bin/quickemu --vm
# initial configuration -- no need to touch, specific to your deployed OS
guest_os="macos"
disk_img="macos-catalina/disk.qcow2"
img="macos-catalina/RecoveryImage.img"
disk_size="128G"
macos_release="catalina"
# additional configuration
cpu_cores=4
ram="8G"
```

---


## 1. Basics

### Connect To Burp (other proxies are okay too of course)

#### 1. Set up port for incoming connections
Reference: [Burp Suite Setup & Usage for iOS Penetration Testing] (https://www.youtube.com/watch?v=ydsUFR0sces)
- Go to **burp** -> Proxy -> Options
  - Set up port eg. 8082 for **All Incoming Connections**
- On **Linux** look for your IP address on the same network as your WiFi Network
```bash
ifconfig
```
   - Example output (irrelevant info redacted). Here you can see my IP is `192.168.0.195`
```bash
wlp0s20f3: flags=0101<UP,BROADCAST,RUNNING,MULTICAST>  mtu 0100
        inet 192.168.0.195  netmask 255.255.255.0  broadcast 192.168.0.255
        inet6 xxxx::xxxx:xxxx:xxxx:xxxx  prefixlen 64  scopeid 0xxx<link>
        ether xx:xx:xx:xx:xx:xx  txqueuelen 0101  (Ethernet)
        RX packets 010101  bytes 0101010101 (115.5 MB)
        RX errors 0  dropped 010  overruns 0  frame 0
        TX packets 01010  bytes 01010010 (14.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

- On **iPhone**
  - Go to Settings -> Your WiFi Network -> Proxy manual connections
  - Host: `192.168.0.195` - my IP I extracted from `ifconfig`
  - Port: 8082 - my port I set up in **burp**
  - Go to **browser**
    - Go to ``http://burp``
    - Download **CA Certificate** - top right corner
  - Go to Settings -> General -> VPN & Device Management -> Portswigger CA -> Install
  - Go to About -> Certificate Trust Settings -> Toggle **PortSwigger CA** on

Now Proxying should work, verify by using your browser and seeing traffic in your proxy.

### Install/Uninstall an IPA

Install an IPA:

```fundamental
ideviceinstaller -i someapp.ipa
```

Uninstall an IPA:

```fundamental
ideviceinstaller -U com.someapp.dev
```

---

On your Linux, start a local web server, and put an IPA in the web root directory (e.g., `somedir`):

```fundamental
mkdir somedir

python3 -m http.server 9000 --directory somedir
```

On your iOS device, download the IPA, long press on it, choose "Share", and install it using [ReProvision Reborn](https://havoc.app/package/rpr) iOS app. Jailbreak is required.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/ReProvision_Reborn_sideloading.jpg" alt="Sideloading an IPA using ReProvision Reborn" height="600em"></p>

<p align="center">Figure 3 - Sideloading an IPA using ReProvision Reborn</p>

If you have an Apple developer membership, you can code sign your apps for up to 1 year; otherwise, you might have to code sign them every now and then.

---

### Download/Upload Files and Directories

Tilde `~` is short for the root directory.

Download a file or directory from your iOS device:

```fundamental
scp root@192.168.0.248:~/somefile.txt ./

scp -r root@192.168.0.248:~/somedir ./
```

Upload a file or directory to your iOS device:

```fundamental
scp somefile.txt root@192.168.0.248:~/

scp -r somedir root@192.168.0.248:~/
```

Use `nano` to edit files directly on your iOS device.

## 2. Inspect an IPA

### Pull a Decrypted IPA

Pull a decrypted IPA from your iOS device:

```bash
git clone https://github.com/AloneMonkey/frida-ios-dump && cd frida-ios-dump && pip3 install -r requirements.txt

python3 dump.py -o decrypted.ipa -P alpine -p 22 -H 192.168.1.10 com.someapp.dev
```

If you want to pull an encrypted IPA from your iOS device, see section [9. Repackage an IPA](#8-repackage-an-ipa) and [AnyTrans](#anytrans).

To unpack, e.g., `someapp.ipa` or `decrypted.ipa` (preferred), run:

```fundamental
unzip decrypted.ipa
```

You should now see the unpacked `Payload` directory.

### Binary

Navigate to `Payload/someapp.app/` directory. There, you will find a binary which have the same name and no file type (i.e., `someapp`).

Search the binary for specific keywords:

```bash
rabin2 -zzzqq someapp | grep -Pi 'keyword'

rabin2 -zzzqq someapp | grep -Pi 'hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView'
```

WebViews can sometimes be very subtle, e.g., they could be hidden as a link to terms of agreement, privacy policy, about the software, referral, etc.

Search the binary for endpoints, deeplinks, sensitive data, comments, etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

Search the binary for weak hash algorithms, insecure random functions, insecure memory allocation functions, etc. For the best results, use [MobSF](#mobile-security-framework-mobsf).

---

Download the latest [AppInfoScanner](https://github.com/kelvinBen/AppInfoScanner/releases), install the requirements, and then extract and resolve endpoints from the binary, or directly from the IPA:

```fundamental
pip3 install -r requirements.txt

python3 app.py ios -i someapp
```

### Info.plist

Navigate to `Payload/someapp.app/` directory. There, you will find a property list file with the name `Info.plist`.

Extract URL schemes from the property list file:

```bash
xmlstarlet sel -t -v 'plist/dict/array/dict[key = "CFBundleURLSchemes"]/array/string' -nl Info.plist 2>/dev/null | sort -uf | tee url_schemes.txt
```

Search the property list file for endpoints, sensitive data \[in Base64 encoding\], etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

### AnyTrans

Export an IPA using [AnyTrans](https://www.imobie.com/anytrans) desktop app. Excellent for iOS backups too.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/anytrans_download.png" alt="Download an IPA using AnyTrans"></p>

<p align="center">Figure 5 - Download an IPA using AnyTrans</p>

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/anytrans_export.png" alt="Export an IPA using AnyTrans"></p>

<p align="center">Figure 6 - Export an IPA using AnyTrans</p>

## 3. Search for Files and Directories

Search for files and directories from the root directory:

```bash
find / -iname '*keyword*'
```

Search for files and directories in the app specific directories (run `env` in [Objection](#7-objection)):

```bash
cd /private/var/containers/Bundle/Application/XXX...XXX/

cd /var/mobile/Containers/Data/Application/YYY...YYY/
```

If you want to download a whole directory from your iOS device, see section [Download/Upload Files and Directories](#downloadupload-files-and-directories).

I preffer downloading the app specific directories, and then doing the [file inspection](#4-inspect-files) on my Linux.

Search for files and directories from the current directory:

```bash
find . -iname '*keyword*'

for keyword in 'access' 'account' 'admin' 'card' 'cer' 'conf' 'cred' 'customer' 'email' 'history' 'info' 'json' 'jwt' 'key' 'kyc' 'log' 'otp' 'pass' 'pem' 'pin' 'plist' 'priv' 'refresh' 'salt' 'secret' 'seed' 'setting' 'sign' 'sql' 'token' 'transaction' 'transfer' 'tar' 'txt' 'user' 'zip' 'xml'; do find . -iname "*${keyword}*"; done
```

### NSUserDefaults

Search for files and directories in [NSUserDefaults](https://developer.apple.com/documentation/foundation/nsuserdefaults) insecure storage directory:

```bash
cd /var/mobile/Containers/Data/Application/YYY...YYY/Library/Preferences/
```

Search for sensitive data in property list files inside NSUserDefaults insecure storage directory:

```fundamental
scp root@192.168.1.10:/var/mobile/Containers/Data/Application/YYY...YYY/Library/Preferences/com.someapp.dev.plist ./

plistutil -f xml -i com.someapp.dev.plist
```

### Cache.db

By default, NSURLSession class stores data such as HTTP requests and responses in Cache.db unencrypted database file.

Search for sensitive data in property list files inside Cache.db unencrypted database file:

```fundamental
scp root@192.168.1.10:/var/mobile/Containers/Data/Application/YYY...YYY/Library/Caches/com.someapp.dev/Cache.db ./

property-lister -db Cache.db -o plists
```

Cache.db is unencrypted and backed up by default, and as such, should not contain any sensitive data after user logs out - it should be cleared by calling [removeAllCachedResponses\(\)](https://developer.apple.com/documentation/foundation/urlcache/1417802-removeallcachedresponses).

## 4. Inspect Files

Inspect memory dumps, binaries, files inside [an unpacked IPA](#pull-a-decrypted-ipa), files inside the app specific directories, or any other files.

After you finish testing \[and logout\], don't forget to [download](#downloadupload-files-and-directories) the app specific directories and inspect all the files inside. Inspect what is new and what still persists after the logout.

**Don't forget to extract Base64 strings from property list files as you might find sensitive data.**

There will be some false positive results since the regular expressions are not perfect. I prefer to use `rabin2` over `strings` because it can read Unicode characters.

On your iOS device, try to modify app's files to test the filesystem checksum validation, i.e., to test the file integrity validation.

### Single File

Search for hardcoded sensitive data:

```bash
rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:basic|bearer)\ .+'

rabin2 -zzzqq somefile | grep -Pi '(?:access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)[\w\d]*(?:\"\ *\:|\ *\=).+'

rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:bug|comment|fix|issue|note|problem|to(?:\_|\ |)do|work)[^\w\d\n]+.+'
```

Extract URLs, deeplinks, IPs, etc.:

```bash
rabin2 -zzzqq somefile | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | sort -uf | tee urls.txt

rabin2 -zzzqq somefile | grep -Po '(?:\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
rabin2 -zzzqq somefile | sort -uf > strings.txt

grep -Po '(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}\=|[a-zA-Z0-9\+\/]{2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### Multiple Files

Search for hardcoded sensitive data:

```bash
IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '[^\w\d\n]+(?:basic|bearer)\ .+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '(?:access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)[\w\d]*(?:\"\ *\:|\ *\=).+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '[^\w\d\n]+(?:bug|comment|fix|issue|note|problem|to(?:\_|\ |)do|work)[^\w\d\n]+.+'; done
```

Extract URLs, deeplinks, IPs, etc.:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | grep -Piv '\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)' | sort -uf | tee urls.txt

IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '(?:\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | sort -uf > strings.txt

grep -Po '(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}\=|[a-zA-Z0-9\+\/]{2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### File Scraper

Automate all of the above file inspection (and more) with a single tool, also using multithreading.

```bash
apt-get -y install radare2

pip3 install file-scraper
```
  
```fundamental
file-scraper -dir Payload -o results.html -e default
```

More about my other project at [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

### SQLite 3

Use [SCP](#downloadupload-files-and-directories) to download database files, and then open them using [DB Browser for SQLite](https://sqlitebrowser.org).

To inspect the content, navigate to `Browse Data` tab, expand `Table` dropdown menu, and select the desired table.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/sqlite.png" alt="SQLite"></p>

<p align="center">Figure 7 - DB Browser for SQLite</p>

To inspect/edit database files on your iOS device, use [SQLite 3](#sileo-sources-and-tools); [SSH](#ssh-to-your-ios-device) to your iOS device and run the following commands:

```sql
sqlite3 somefile

.dump

.tables

SELECT * FROM sometable;

.quit
```

[Property Lister](#property-lister) will dump all databases in plain-text automatically.

### Property Lister

Unpack, e.g., `someapp.ipa` or [decrypted.ipa](#pull-a-decrypted-ipa) (preferred).

Dump all the databases, and extract and convert all the property list files inside an IPA:

```fundamental
property-lister -db Payload -o results_db

property-lister -pl Payload -o results_pl
```

Repeat the same for [the app specific directories](#3-search-for-files-and-directories).

### Nuclei

Download mobile Nuclei templates:

```fundamental
git clone https://github.com/optiv/mobile-nuclei-templates ~/mobile-nuclei-templates
```

Unpack, e.g., `someapp.ipa` or [decrypted.ipa](#pull-a-decrypted-ipa) (preferred).

Search for hardcoded sensitive data:

```bash
echo Payload | nuclei -t ~/mobile-nuclei-templates/Keys/ -o nuclei_keys_results.txt

cat nuclei_keys_results.txt | grep -Po '(?<=\]\ ).+' | sort -uf > nuclei_keys_results_sorted.txt
```

### Backups

Get your iOS device UDID:

```fundamental
idevice_id -l
```

Create a backup:

```bash
idevicebackup2 backup --full -u $(idevice_id -l) ./backup
```

App should not backup any sensitive data.

Restore from a backup:

```bash
idevicebackup2 restore -u $(idevice_id -l) ./backup
```

---

Browse backups using [iExplorer](https://macroplant.com/iexplorer) (demo) for Windows OS. There are many other iOS backup tools, but they cannot browse app specific directories.

iExplorer's default directory for storing iOS backups:

```fundamental
C:\Users\%USERNAME%\AppData\Roaming\Apple Computer\MobileSync\Backup\
```

You can place your backups in either this directory or change it in settings.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/iexplorer.png" alt="iExplorer"></p>

<p align="center">Figure 8 - iExplorer</p>

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/iexplorer_browse.png" alt="Browse a backup using iExplorer"></p>

<p align="center">Figure 9 - Browse a backup using iExplorer</p>

## 5. Deeplinks

Test [/.well-known/apple-app-site-association](https://developer.apple.com/documentation/xcode/supporting-associated-domains) using [branch.io/resources/aasa-validator](https://branch.io/resources/aasa-validator).

Sometimes, deeplinks can bypass authentication, including biometrics.

Create an HTML template to manually test deeplinks:

```bash
mkdir ios_deeplinks

# multiple URL schemes

for scheme in $(cat url_schemes.txt); do for url in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do if [[ ! -z $url ]]; then echo -n "<a href='${url}'>${url}</a>\n<br><br>\n" | tee -a "ios_deeplinks/${scheme}_deeplinks.html"; fi; done; done

# single URL scheme

scheme="somescheme"; for string in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do echo -n "<a href='${string}'>${string}</a>\n<br><br>\n"; done | tee -a "ios_deeplinks/${scheme}_deeplinks.html"

python3 -m http.server 9000 --directory ios_deeplinks
```

For `url_schemes.txt` see section [Info.plist](#infoplist), and for `urls.txt` see section [4. Inspect Files](#4-inspect-files).

---

Fuzz deeplinks using [ios-deeplink-fuzzing](https://codeshare.frida.re/@ivan-sincek/ios-deeplink-fuzzing) script with [Frida](#6-frida):

```fundamental
frida -U -no-pause -l ios-deeplink-fuzzing.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/ios-deeplink-fuzzing -f com.someapp.dev
```

Check the source code for more instructions. You can also paste the whole source code directly into Frida and call the methods as you prefer.

## 6. Frida

Useful resources:

* [frida.re](https://frida.re/docs/home)
* [learnfrida.info](https://learnfrida.info)
* [codeshare.frida.re](https://codeshare.frida.re)
* [dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida)
* [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts)
* [m0bilesecurity/Frida-Mobile-Scripts](https://github.com/m0bilesecurity/Frida-Mobile-Scripts)

List processes:

```bash
frida-ps -Uai

frida-ps -Uai | grep -i 'keyword'
```

Get PID for a specified keyword:

```bash
frida-ps -Uai | grep -i 'keyword' | cut -d ' ' -f 1
```

Discover internal methods/calls:

```bash
frida-discover -U -f com.someapp.dev | tee frida_discover.txt
```

Trace internal methods/calls:

```bash
frida-trace -U -p 1337

frida-trace -U -p 1337 -i 'recv*' -i 'send*'
```

### Frida Scripts

Bypass biometrics using [ios-touch-id-bypass](https://codeshare.frida.re/@ivan-sincek/ios-touch-id-bypass) script:

```fundamental
frida -U -no-pause -l ios-touch-id-bypass.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/ios-touch-id-bypass -f com.someapp.dev
```

On the touch ID prompt, press `Cancel`.

I prefer to use the built-in method in [Objection](#bypasses).

---

Hook all classes and methods using [ios-hook-classes-methods](https://codeshare.frida.re/@ivan-sincek/ios-hook-classes-methods) script:

```fundamental
frida -U -no-pause -l ios-hook-classes-methods.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/ios-hook-classes-methods -f com.someapp.dev
```

## 7. Objection

Useful resources:

* [sensepost/objection](https://github.com/sensepost/objection)

Run:

```fundamental
objection -g com.someapp.dev explore
```

Run a [Frida](#6-frida) script in Objection:

```fundamental
import somescript.js

objection -g com.someapp.dev explore --startup-script somescript.js
```

Get information:

```fundamental
ios info binary

ios plist cat Info.plist
```

Get environment variables:

```fundamental
env
```

Get HTTP cookies:

```fundamental
ios cookies get
```

Dump Keychain, NSURLCredentialStorage, and NSUserDefaults:

```fundamental
ios keychain dump

ios nsurlcredentialstorage dump

ios nsuserdefaults get
```

Sensitive data such as app's PIN, password, etc., should not be stored as a plain-text in the keychain; instead, they should be hashed as an additional level of protection.

Dump app's memory to a file:

```fundamental
memory dump all mem.dmp
```

Dump app's memory after, e.g., 10 minutes of inactivity, then, check if sensitive data is still in the memory, see section [4. Inspect Files](#4-inspect-files).

**In case Objection detaches from the app, use the process ID to attach it back without restarting the app.**

Search app's memory directly:

```bash
memory search 'somestring' --string
```

List classes and methods:

```bash
ios hooking list classes
ios hooking search classes 'keyword'

ios hooking list class_methods 'someclass'
ios hooking search methods 'keyword'
```

Hook on a class or method:

```bash
ios hooking watch class 'someclass'

ios hooking watch method '-[someclass somemethod]' --dump-args --dump-backtrace --dump-return
```

Change the method's return value:

```bash
ios hooking set return_value '-[someclass somemethod]' false
```

Monitor crypto libraries:

```fundamental
ios monitor crypto
```

Monitor the pasteboard:

```fundamental
ios pasteboard monitor
```

You can also dump the pasteboard using [cycript](#dump-the-pasteboard).

### Bypasses

Bypass a jailbreak detection:

```bash
ios jailbreak disable --quiet

objection -g com.someapp.dev explore --startup-command 'ios jailbreak disable --quiet'
```

Also, on your iOS device, check `A-Bypass` in `Settings` app.

---

Bypass SSL pinning:

```bash
ios sslpinning disable --quiet

objection -g com.someapp.dev explore --startup-command 'ios sslpinning disable --quiet'
```

---

Bypass biometrics:

```bash
ios ui biometrics_bypass --quiet

objection -g com.someapp.dev explore --startup-command 'ios ui biometrics_bypass --quiet'
```

Also, you can import [Frida](#frida-scripts) script.

## 8. Repackage an IPA

[SSH](#ssh-to-your-ios-device) to your iOS device and run the following commands.

Navigate to the app specific directory:

```bash
cd /private/var/containers/Bundle/Application/XXX...XXX/
```

Repackage the IPA:

```fundamental
mkdir Payload

cp -r someapp.app Payload

zip -r repackaged.ipa Payload

rm -rf Payload
```

On your Linux, download the repackaged IPA:

```fundamental
scp root@192.168.1.10:/private/var/containers/Bundle/Application/XXX...XXX/repackaged.ipa ./
```

If you want to pull a decrypted IPA from your iOS device, see section [Pull a Decrypted IPA](#pull-a-decrypted-ipa).

## 9. Miscellaneous

### Monitor the System Log

On your Linux, run the following command:

```fundamental
idevicesyslog -p 1337
```

Or, get the PID from a keyword:

```fundamental
keyword="keyword"; idevicesyslog -p $(frida-ps -Uai | grep -i "${keyword}" | tr -s '[:blank:]' ' ' | cut -d ' ' -f 1)
```

### Monitor File Changes

[SSH](#ssh-to-your-ios-device) to your iOS device, then, download and run [Filemon](http://www.newosxbook.com):

```bash
wget http://www.newosxbook.com/tools/filemon.tgz && tar zxvf filemon.tgz && chmod +x filemon

./filemon -c -f com.someapp.dev
```

Always look for created or cached files, images/screenshots, etc. Use `nano` to edit files directly on your iOS device.

Sensitive files such as know your customer (KYC) and similar, should not persists in the app specific directories on the user device after the file upload. Sensitive files should not be stored in `/tmp/` directory nor similar system-wide directories.

Images and screenshots path:

```fundamental
cd /var/mobile/Containers/Data/Application/YYY...YYY/Library/SplashBoard/Snapshots/
```

### Dump the Pasteboard

After copying sensitive data, the app should wipe the pasteboard after a short period of time.

[SSH](#ssh-to-your-ios-device) to your iOS device and run the following commands:

```fundamental
cycript -p 1337

[UIPasteboard generalPasteboard].items
```

Press `CTRL + D` to exit.

You can also monitor the pasteboard in [Objection](#7-objection).

### Get the Provisioning Profile

```fundamental
scp root@192.168.1.10:/private/var/containers/Bundle/Application/XXX...XXX/*.app/embedded.mobileprovision ./

openssl smime -inform der -verify -noverify -in embedded.mobileprovision
```

## 10. Tips and Security Best Practices

Bypass any keyboard restriction by copying and pasting data into an input field.

Access tokens should be short lived, and if possible, invalidated on logout.

Don't forget to test widgets, push notifications, app extensions, and Firebase.

Sometimes, deeplinks and widgets can bypass authentication, including biometrics.

Only if explicitly allowed, try flooding 3rd party APIs to cause possible monetary damage to the company, or denial-of-service (DoS) by exhausting the allowed quotas/limits.

---

App should not disclose sensitive data in the predictive text (due to incorrectly defined input field type), app switcher, and push notifications.

App should warn a user when taking a screenshot of sensitive data.

App should warn a user that it is trivial to bypass biometrics authentication if iOS device is jailbroken.

Production app (i.e., build) should not be debuggable.

## 11. Useful Websites and Tools

| URL                                                                                                    | Description                                                        |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| [developer.apple.com/account](https://developer.apple.com/account)                                     | Official iOS documentation, create code signing certificates, etc. |
| [developer.apple.com/apple-pay/sandbox-testing](https://developer.apple.com/apple-pay/sandbox-testing) | Test debit/credit cards for Apple Pay.                             |
| [streaak/keyhacks](https://github.com/streaak/keyhacks)                                                | Validate various API keys.                                         |
| [zxing.org/w/decode.jspx](https://zxing.org/w/decode.jspx)                                             | Decode QR codes.                                                   |
| [youtube.com/user/iDeviceMovies](https://www.youtube.com/user/iDeviceMovies)                           | Useful videos about jailbreaking, etc.                             |
| [ipsw.me/product/iPhone](https://ipsw.me/product/iPhone)                                               | Firmwares for Apple devices.                                       |
