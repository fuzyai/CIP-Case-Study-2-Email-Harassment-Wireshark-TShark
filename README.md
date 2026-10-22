CIP-B103 Lab 2 – Packet Analysis with TShark (Nitroba Case)

Student: Fuseini Imoru Kantuogaa
Registration: C11/26/DFIT/17291
Course: CIP-B103
Lab: Lab 2 – Network Traffic Analysis & Anonymous Message Attribution
Date: 13–14 September 2026
Environment: Kali Linux

## Overview

This lab demonstrates command-line packet analysis with TShark and Wireshark. It starts with TShark fundamentals (interface listing, capture and display filters, field extraction, statistics, regular expressions, stream following) and then applies them to the public Nitroba scenario capture (`nitroba.pcap`). The goal was to identify who submitted an anonymous, threatening message through the website `willselfdestruct.com`, and which device on the local network sent it.

## 1. Case Setup & Evidence Acquisition

A working directory was created and the capture downloaded:

```bash
sudo su
mkdir harass
cd harass
wget https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2008-nitroba/nitroba.pcap
ls -l nitroba.pcap
openssl dgst -md5 nitroba.pcap
```

The first `wget` call printed a warning (`Prepended http:// to '-q'`) because of the quiet flag, but the download then completed normally.

| Property | Value |
|---|---|
| File | nitroba.pcap |
| Size | 56,180,821 bytes (54 MB) |
| Downloaded | 2026-09-13, 11:47–11:50 (3m 3s, ~1.36 MB/s) |
| MD5 | 9981827f11968773ff815e39f5458ec8 |

The MD5 was recomputed later in the same directory and matched.

## 2. TShark Fundamentals

The manual page was reviewed (`man tshark`) and the available capture interfaces listed:

```bash
tshark -D
```

Interfaces included `eth0`, `any`, `lo`, `docker0` and several remote-capture helpers (`sshdump`, `udpdump`, `wifidump`, and others).

### Capture to file

```bash
tshark -i eth0 -c 10 -w mycapture.pcap
ll mycapture.pcap
tshark -r mycapture.pcap
```

Ten packets were captured (1,296 bytes): repeated ARP requests from the gateway (`Who has 192.168.196.2? Tell 192.168.196.1`) and an NTP exchange between 192.168.196.128 and 162.159.200.123.

### Capture filters

```bash
tshark -f "net 192.168.196.0/24" -i eth0 -c 10 -w mycapture192_168_196_0.pcap
sudo tshark -i eth0 -f "ip src host 192.168.196.2" -c 10 -w /tmp/mycapture192_168_196_2.pcap
```

While `ping -c 10 192.168.196.2` ran in another session, the `ip src host` filter captured only the 10 ICMP echo replies (TTL 128, seq 1–10). The ping reported 10 sent, 10 received, 0% loss, RTT min/avg/max = 0.193/0.468/0.739 ms.

## 3. Practice Capture Analysis (basic.log)

A small loopback capture was downloaded from Dropbox (`basic.log`, 1,812 bytes) and analyzed:

```bash
tshark -r basic.log
tshark -qz io,phs -r basic.log
tshark -r basic.log -qz io,stat,0,"COUNT(frame) frame"
tshark -r basic.log -qz io,stat,0,"COUNT(frame)","data-text-lines contains \"first\""
```

| Result | Value |
|---|---|
| Total frames | 10 (1,111 bytes), all Ethernet / IP / TCP |
| HTTP frames | 2 (567 bytes) |
| Frames with text data | 1 (418 bytes), frame 6 |

Display filters (`-Y`) and field extraction (`-T fields -e`) were practiced:

```bash
tshark -r basic.log -T fields -e frame.time -e frame
tshark -r basic.log -T fields -e frame.number -e ip.src -e ip.dst -e ip.len
tshark -r basic.log -Y "frame.number == 6"
tshark -r basic.log -Y "data-text-lines contains \"first\""
tshark -r basic.log -Y "data-text-lines matches \"(paragraph|Head)\""
tshark -r basic.log -Y "http.user_agent matches \"curl\""
tshark -r basic.log -Y "frame.number == 6" -V
tshark -r basic.log -Y "frame.number == 6" -x
tshark -r basic.log -z follow,tcp,ascii,0 -Y http
```

Findings from `basic.log`:

- Frame 4 is `GET /basic.html` from `curl/7.67.0` to 127.0.0.1.
- Frame 6 is the `200 OK` response from `Apache/2.4.41 (Debian)`, Content-Length 101, Last-Modified Mon, 26 Oct 2020 00:22:36 GMT.
- The response body is a short HTML page ("My First Heading" / "My first paragraph.").
- Loopback frames show all-zero MAC addresses (`00:00:00:00:00:00`).

Verbose output was combined with `grep -E` and `--color` to pull out specific strings (HTML tags, IP addresses, `http://` URLs, and User-Agent). An email regular expression was also tested (`echo ... | grep -E`), and `regex101.com` was used to build patterns. The field and protocol names available to filter on were explored with:

```bash
tshark -G protocols | grep http
tshark -G fields | grep -E "http\."
tshark -G fields | grep -E "\btcp\."
```

## 4. Live Capture Practice (ubalt.pcap)

A capture of a live web visit was taken and inspected:

```bash
tshark -f "host 204.52.129.211" -i eth0 -w ubalt.pcap -c 500
tshark -r ubalt.pcap -T fields -e ip.addr | sort | uniq
tshark -r ubalt.pcap -Y "eth" -T fields -e eth.addr | sort | uniq
tshark -r ubalt.pcap -Y "frame.number == 14 && data-text-lines" -V | grep -E "[0-9]{3}\.[0-9]{3}\.[0-9]{4}"
```

The capture contained a single conversation between 10.0.2.5 and 204.52.129.211 (the www.ubalt.edu server), between MAC addresses 52:54:00:12:35:00 and 08:00:27:4e:f7:72. A regular expression on frame 14 extracted a phone number from the page content.

## 5. Nitroba Capture Overview

```bash
ls -l nitroba.pcap
tshark -r nitroba.pcap | head -n 2
tshark -r nitroba.pcap | tail -n 2
tshark -r nitroba.pcap -qz io,stat,0,"COUNT(frame) frame"
tshark -r nitroba.pcap -T fields -e frame.time -e frame | head -n 3
```

| Property | Value |
|---|---|
| Total frames | 94,410 |
| Duration | 15,760 seconds (about 4 h 23 min) |
| First frame | 2008-07-21 21:51:07 (UTC-4) |
| Last frames | SSDP notify and a TCP retransmission from 192.168.15.4 to 74.125.19.99 |

## 6. Identifying the Anonymous Message

### Requests to the anonymous email service

```bash
tshark -r nitroba.pcap -Y "http.request.method == \"GET\" && http.host==\"www.willselfdestruct.com\""
tshark -r nitroba.pcap -Y "http.request.method == \"GET\" && http.host==\"www.willselfdestruct.com\"" \
  -T fields -e frame.time -e frame.time_delta_displayed -e ip.src -e ip.dst -e http.request.uri
```

Host 192.168.15.4 requested `http://www.willselfdestruct.com/secure/submit` (frame 82936) and related images (spacer, logo, warning, button and message GIFs), then `/secure/success` (frame 83614), all to server 69.25.94.22.

The service pages were identified by searching HTTP text for its marketing title:

```bash
tshark -r nitroba.pcap -Y "data-text-lines matches \"secure anonymous E-mail\"" 2>/dev/null
```

| Frame | Time (UTC) | Content |
|---|---|---|
| 82998 | 2008-07-22 06:03:44 | Submit form page (20,475 bytes reassembled, 539 lines), titled "FREE secure anonymous E-mail ..." |
| 83641 | 2008-07-22 06:04:24 | Success page (15,830 bytes, 429 lines), response to `/secure/success` |

### The submitted message (POST)

```bash
tshark -r nitroba.pcap -Y "(ip.src == 192.168.15.4) && (ip.dst == 69.25.94.22) && http.request.method == \"POST\""
tshark -r nitroba.pcap -Y "frame.number == 83601" -V | grep -i "form item"
tshark -r nitroba.pcap -Y "frame.number == 83601" -V -T fields -e urlencoded-form.key -e urlencoded-form.value
```

Frame 83601 is an HTTP POST to `/secure/submit` from 192.168.15.4 (port 36044) to 69.25.94.22 (port 80), 719 bytes, sent at 2008-07-22 06:04:24 UTC (02:04:24 UTC-4).

| Form field | Value |
|---|---|
| to | lilytuckrige@yahoo.com |
| from | (empty) |
| subject | you can't find us |
| message | "and you can't hide from us. Stop teaching. Start running." |
| type / ttl | 0 / 30 |

Other form data in the capture also showed `sender = the_whole_world_is_watching@nitroba.org` and `email = lilytuckrige@yahoo.com`.

## 7. Attributing the Traffic to a Device

```bash
tshark -r nitroba.pcap -Y "frame.number == 83601" -T fields -e eth.src
tshark -r nitroba.pcap -Y "eth.addr == 00:17:f2:e2:c0:ce" | wc -l
tshark -r nitroba.pcap -qz io,stat,0,"COUNT(eth) eth","eth.addr == 00:17:f2:e2:c0:ce"
```

| Item | Value |
|---|---|
| Source IP of the POST | 192.168.15.4 |
| Source MAC of the POST | 00:17:f2:e2:c0:ce (Apple) |
| Destination MAC | 00:1d:d9:2e:4f:60 (Hon Hai Precision, the local gateway) |
| Frames to/from this MAC | 73,246 of 94,410 (44,742,268 bytes) |

The same MAC/IP pair generated the requests to willselfdestruct.com and most of the capture's traffic, so the message came from one identifiable device on the local network.

## 8. Account Indicators in Cookies

HTTP cookies sent by this device were searched for email addresses:

```bash
tshark -r nitroba.pcap -Y "eth.src == 00:17:f2:e2:c0:ce && http.cookie contains \"@\"" | wc -l      # 149
tshark -r nitroba.pcap -Y "eth.src == 00:17:f2:e2:c0:ce" -V | grep -P "[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,4}"
```

| Indicator | Where it appeared |
|---|---|
| jcoachj@gmail.com | Cookies `gmailchat=jcoachj@gmail.com/475090` and `OL_SESSION=jcoachj@gmail.com-cal`; Gmail requests to 74.125.19.x |
| cambridgecommons@hotmail.com | MSN Messenger login (`USR 3 TWN I ...`, client MSNMSGR 6.0.0602) |

149 frames from this MAC carried cookies containing an `@`. These accounts are indicators of who used the device, not proof of identity on their own.

## Reconstructed Timeline (UTC, 2008-07-22)

| Time | Event | Frame |
|---|---|---|
| 06:03:43 | 192.168.15.4 requests `/secure/submit` on willselfdestruct.com | 82936 |
| 06:03:44 | Submit form page returned by 69.25.94.22 | 82998 |
| 06:04:24 | Form POSTed to lilytuckrige@yahoo.com | 83601 |
| 06:04:24 | `/secure/success` page returned | 83641 |
| 06:01–06:07 | Gmail cookies seen from the same MAC throughout | multiple |

## Evidence Summary

| Item | Finding |
|---|---|
| Evidence file | nitroba.pcap, MD5 `9981827f11968773ff815e39f5458ec8` |
| Capture size | 94,410 frames, 15,760 seconds |
| Service used | www.willselfdestruct.com (69.25.94.22) |
| Recipient | lilytuckrige@yahoo.com |
| Sending host | 192.168.15.4 / MAC 00:17:f2:e2:c0:ce (Apple) |
| Submission | Frame 83601, 2008-07-22 06:04:24 UTC |
| Associated accounts | jcoachj@gmail.com, cambridgecommons@hotmail.com |

## Key Tools Used

| Tool | Purpose |
|---|---|
| tshark | Capture, display filters, field extraction, statistics, stream following |
| Wireshark | Visual inspection of HTTP requests, POST form data and cookies |
| `-G protocols` / `-G fields` | Discovering field names for filters |
| grep / sort / uniq / wc | Filtering and counting output |
| regex101.com | Building and testing regular expressions |
| openssl dgst | MD5 hashing of the evidence file |
| wget | Acquiring evidence and practice files |

## Forensic Notes

- The capture was hashed on acquisition and again before analysis; both MD5 values matched.
- Wireshark displays times in UTC, while TShark printed local time (UTC-4) in `-T fields` output. Both describe the same instant (for example 06:04:24 UTC equals 02:04:24 UTC-4).
- Each finding was confirmed two ways, in the Wireshark GUI and with TShark command output (the POST fields, the MAC address and the cookie values).
- MAC address attribution is limited to the local network segment and could be spoofed, so it should be corroborated with other evidence (DHCP logs, physical access records).
- Email addresses in cookies identify accounts used on the device, not necessarily the person at the keyboard.
- Only a scenario capture from a public training corpus was analyzed, and all live captures were taken on the student's own lab network.
