---
title: "Fixing TP-Link TL-WN722N (v2/v3) RTL8188EUS Monitor Mode on Kali Linux"
date: 2026-09-17 09:00:00 +0200
categories: [Wireless Security, Linux]
tags: [kali-linux, wifi]
---

While working on a wireless security lab using Kali Linux inside VMware, I encountered a frustrating problem with a **TP-Link TL-WN722N v2/v3** USB Wi-Fi adapter.

The adapter was detected correctly by Kali Linux, and I could put the interface into monitor mode. However, when I started `airodump-ng`, **no wireless networks or packets appeared**.

At first, everything looked normal.

The adapter was detected:

```bash
lsusb
```

Output:

```text
Bus 001 Device 002: ID 2357:010c TP-Link TL-WN722N v2/v3 [Realtek RTL8188EUS]
```

The interface also existed:

```bash
iw dev
```

And it could be switched to monitor mode.

But:

```bash
sudo airodump-ng wlan0
```

produced no useful results.

This article explains how I diagnosed the problem and, more importantly, how I fixed it.

---

# 1. The Problem

My setup was:

* Kali Linux
* Kali Linux running inside VMware
* TP-Link TL-WN722N v2/v3
* Realtek RTL8188EUS chipset
* `wlan0` wireless interface

The first thing I checked was whether Kali could see the USB device.

```bash
lsusb
```

The adapter appeared as:

```text
2357:010c TP-Link TL-WN722N v2/v3 [Realtek RTL8188EUS]
```

So USB passthrough was working.

---

# 2. Checking the Wireless Interface

Next, I checked the wireless interfaces:

```bash
iw dev
```

The interface was present:

```text
phy#0
    Interface wlan0
        type monitor
        channel 12 (2467 MHz)
```

This was important.

The adapter wasn't completely missing.

It was already operating in monitor mode.

I also confirmed that I could manually change the channel:

```bash
sudo iw dev wlan0 set channel 6
```

Then:

```bash
sudo iw dev wlan0 info
```

showed:

```text
type monitor
channel 6
```

So channel switching was working as well.

---

# 3. `airodump-ng` Shows Nothing

I tried:

```bash
sudo airodump-ng wlan0
```

But nothing useful appeared.

I initially suspected that another process might be interfering with monitor mode.

So I checked:

```bash
sudo airmon-ng check
```

I found processes including:

```text
NetworkManager
wpa_supplicant
```

I stopped the interfering processes:

```bash
sudo airmon-ng check kill
```

Then I manually configured monitor mode again:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
```

Then I tested packet capture directly.

---

# 4. Testing With tcpdump

Instead of relying only on `airodump-ng`, I used `tcpdump`:

```bash
sudo tcpdump -i wlan0 -e -c 20
```

The interface was recognized as:

```text
link-type IEEE802_11_RADIO
```

which is exactly what we would expect for an 802.11 monitor interface.

But the important part was:

```text
0 packets captured
0 packets received by filter
0 packets dropped
```

This was a major clue.

The interface existed.

Monitor mode existed.

The channel could be changed.

But **no 802.11 frames were being received**.

---

# 5. Checking the Driver

The next step was to identify which driver was actually being used.

I ran:

```bash
sudo ethtool -i wlan0
```

The output showed:

```text
driver: rtl8xxxu
version: 6.16.8+kali-amd64
firmware-version: N/A
bus-info: 1-1:1.0
```

This immediately became suspicious.

The adapter is based on the **RTL8188EUS** chipset, while Kali was using the generic:

```text
rtl8xxxu
```

driver.

The generic driver can initialize the adapter, but in this situation it was not providing the packet capture behavior I needed.

---

# 6. Checking the Kernel Messages

I then inspected the kernel logs:

```bash
dmesg | grep -i -E 'rtl|8188|wlan|firmware'
```

The logs showed that Kali correctly detected the chipset:

```text
RTL8188EU rev D
```

The kernel also loaded the firmware:

```text
rtl8xxxu: Loading firmware rtlwifi/rtl8188eufw.bin
```

and:

```text
Firmware revision 28.0
```

So this wasn't simply a missing firmware problem.

The USB device was detected.

The chipset was identified.

The firmware was loaded.

The problem was the driver being used.

---

# 7. Checking rfkill

I also verified that the adapter wasn't blocked:

```bash
rfkill list
```

The result was:

```text
Wireless LAN
    Soft blocked: no
    Hard blocked: no
```

So this wasn't an rfkill issue either.

At this point, the troubleshooting looked like this:

| Component            | Status          |
| -------------------- | --------------- |
| USB passthrough      | Working         |
| Adapter detection    | Working         |
| RTL8188EUS detection | Working         |
| Firmware             | Loaded          |
| rfkill               | Not blocked     |
| Monitor mode         | Working         |
| Channel switching    | Working         |
| Packet capture       | **Not working** |
| Driver               | **rtl8xxxu**    |

The driver became the primary suspect.

---

# 8. Installing the RTL8188EUS DKMS Driver

I looked for an appropriate DKMS driver for the actual chipset.

One important lesson here is:

**Do not install a driver just because the name contains `88xx`.**

For example, Kali may have packages intended for completely different Realtek chipsets.

My adapter is:

```text
RTL8188EUS
```

so I needed a driver specifically supporting this chipset.

After installing the appropriate RTL8188EUS DKMS package, I checked:

```bash
dkms status
```

It showed:

```text
realtek-rtl8188eus/5.3.9~git20260622.cbeae98, 7.1.5+kali-amd64, x86_64: installed
```

This was progress.

The driver had been successfully built and installed for the current kernel.

However, there was still a problem.

---

# 9. The DKMS Driver Was Installed — But Wasn't Being Used

I checked the active driver again:

```bash
sudo ethtool -i wlan0
```

And it still showed:

```text
driver: rtl8xxxu
```

This was the key discovery.

The RTL8188EUS-specific DKMS driver was installed, but the kernel was still choosing the generic:

```text
rtl8xxxu
```

driver.

So simply installing the correct driver wasn't enough.

We needed to prevent the generic driver from claiming the device.

---

# 10. Confirming the 8188eu Module

First, I checked whether the DKMS module was available:

```bash
modinfo 8188eu
```

If this command returns information about the module, the DKMS driver is available to the kernel.

This is an important step before changing anything.

---

# 11. Blacklisting the Generic Driver

Because `rtl8xxxu` was claiming the adapter, I blacklisted it.

I created:

```bash
sudo nano /etc/modprobe.d/blacklist-rtl8xxxu.conf
```

with:

```text
blacklist rtl8xxxu
```

Or, using one command:

```bash
echo "blacklist rtl8xxxu" | sudo tee /etc/modprobe.d/blacklist-rtl8xxxu.conf
```

Then I rebuilt the initramfs:

```bash
sudo update-initramfs -u
```

And rebooted:

```bash
sudo reboot
```

---

# 12. Verifying the Driver After Reboot

After rebooting, I checked:

```bash
sudo ethtool -i wlan0
```

The important result was that the adapter was now using:

```text
driver: 8188eu
```

instead of:

```text
driver: rtl8xxxu
```

I also checked:

```bash
lsmod | grep -E '8188eu|rtl8xxxu'
```

The goal was to confirm that the RTL8188EUS-specific driver was loaded and the generic driver wasn't claiming the device.

---

# 13. Testing Monitor Mode Again

I stopped processes that can interfere with monitor mode:

```bash
sudo airmon-ng check kill
```

Then:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

I selected a channel:

```bash
sudo iw dev wlan0 set channel 6
```

Then I tested packet capture:

```bash
sudo tcpdump -i wlan0 -e -c 20
```

This time, wireless frames started appearing.

That was the moment the problem was finally solved.

🎉

---

# 14. Testing With airodump-ng

With packet capture working, I could finally run:

```bash
sudo airodump-ng wlan0
```

and see nearby wireless traffic.

The important difference wasn't the `airodump-ng` command itself.

The real fix was getting the adapter to use the correct driver:

```text
RTL8188EUS
      ↓
8188eu DKMS driver
      ↓
monitor mode
      ↓
802.11 packet capture
      ↓
airodump-ng
```

---

# 15. Why `rtl8xxxu` Was the Problem

The generic `rtl8xxxu` driver successfully initialized the adapter.

That can make troubleshooting confusing because everything appears to be working:

* `lsusb` sees the device.
* `iw dev` sees `wlan0`.
* Monitor mode can be enabled.
* Channels can be changed.
* Firmware can load.

But none of those checks prove that **monitor-mode packet reception is actually functioning correctly**.

The most useful test was therefore:

```bash
sudo tcpdump -i wlan0 -e
```

If the interface is in monitor mode but consistently receives:

```text
0 packets
```

then the driver/interface combination needs investigation.

---

# 16. A Useful Troubleshooting Workflow

If you encounter a similar problem, don't immediately reinstall Kali or randomly install Realtek drivers.

Work through the stack systematically.

### Step 1 — Confirm USB detection

```bash
lsusb
```

### Step 2 — Identify the chipset

```bash
lsusb
```

Look for the chipset/device information.

### Step 3 — Check the interface

```bash
iw dev
```

### Step 4 — Check the active driver

```bash
sudo ethtool -i wlan0
```

### Step 5 — Check kernel messages

```bash
dmesg | grep -i -E 'rtl|8188|wlan|firmware'
```

### Step 6 — Check rfkill

```bash
rfkill list
```

### Step 7 — Stop interfering wireless processes

```bash
sudo airmon-ng check kill
```

### Step 8 — Enable monitor mode

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### Step 9 — Set a channel

```bash
sudo iw dev wlan0 set channel 6
```

### Step 10 — Test raw packet reception

```bash
sudo tcpdump -i wlan0 -e
```

### Step 11 — Only then test airodump-ng

```bash
sudo airodump-ng wlan0
```

This approach makes it much easier to identify exactly where the problem occurs.

---

# 17. An Important Lesson About Linux Drivers

One of the biggest lessons from this troubleshooting session was:

> **Installed doesn't mean active.**

The correct DKMS driver can be installed successfully:

```text
dkms status
```

can show:

```text
installed
```

while the device is still using another driver.

Always verify the driver actually attached to the interface:

```bash
sudo ethtool -i wlan0
```

In my case:

### Before

```text
driver: rtl8xxxu
```

### After

```text
driver: 8188eu
```

That distinction was the key to solving the problem.

---

# 18. Don't Trust `airodump-ng` Alone

Another important lesson was to troubleshoot from the bottom up.

Instead of asking only:

> "Why doesn't airodump-ng show networks?"

break the problem into layers:

```text
USB
 ↓
Kernel
 ↓
Driver
 ↓
Firmware
 ↓
Wireless interface
 ↓
Monitor mode
 ↓
Channel
 ↓
802.11 packet reception
 ↓
airodump-ng
```

In this case, `airodump-ng` was only showing the final symptom.

The actual problem was lower in the stack.

Using:

```bash
tcpdump
```

helped prove that packets weren't reaching the monitor interface.

---

# 19. Final Working Configuration

The final setup was:

```text
TP-Link TL-WN722N v2/v3
        │
        ▼
RTL8188EUS
        │
        ▼
8188eu DKMS driver
        │
        ▼
wlan0
        │
        ▼
Monitor Mode
        │
        ▼
802.11 packet capture
        │
        ▼
airodump-ng
```

The key commands were:

```bash
dkms status
```

```bash
modinfo 8188eu
```

```bash
echo "blacklist rtl8xxxu" | sudo tee /etc/modprobe.d/blacklist-rtl8xxxu.conf
```

```bash
sudo update-initramfs -u
```

```bash
sudo reboot
```

Then verify:

```bash
sudo ethtool -i wlan0
```

and confirm:

```text
driver: 8188eu
```

Finally:

```bash
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
sudo tcpdump -i wlan0 -e
```

and:

```bash
sudo airodump-ng wlan0
```

---

# Conclusion

This problem initially looked like an `airodump-ng` issue, but it wasn't.

The adapter was detected correctly, firmware was loaded, monitor mode worked, and the wireless interface existed.

The real issue was that Kali was using the generic:

```text
rtl8xxxu
```

driver instead of the RTL8188EUS-specific:

```text
8188eu
```

driver.

Installing the correct DKMS driver and preventing `rtl8xxxu` from claiming the device solved the problem.

The biggest takeaway is simple:

> **When a wireless adapter appears to work but monitor mode captures zero packets, don't stop at "the interface is in monitor mode." Verify the actual driver and verify raw 802.11 packet reception.**

That troubleshooting mindset is useful far beyond this specific Wi-Fi adapter.

---

## Disclaimer

This guide is intended for authorized security testing, wireless labs, CTFs, and networks you own or have explicit permission to test.

Only use monitor mode and wireless security tools in environments where you have authorization.
