---
title: "OpenWrt on Xiaomi CR880x & AX3000"
date: 2025-02-23T19:00:00+07:00
draft: false
lastmod: 2025-02-25T19:00:00+07:00
showLastmod: true
categories:
  - project
tags:
  - xiaomi wifi router
  - openwrt
keywords:
  - openwrt
  - xiaomi wifi router
  - xiaomi cr880x
  - xiaomi cr8808
  - xiaomi ax3000
  - xiaomi m81
  - xiaomi m79
  - xiaomi ra81
  - xiaomi cr8806
  - xiaomi cr8809
  - xiaomi ipq5000
---

There were some problems about performance and heat about my ASUS RT-AC58U V2 wi-fi router so I'm replacing it with something else. This time i'm trying out some cheap xiaomi wifi router named Xiaomi CR8808 and trying to flash an OpenWrt image on it.

## Overview

First, I will go through the Xiaomi Wi-Fi 6 AX3000 lineup, which includes:

* CR880X M79 (CR8808, CR8806, CR8809 which are the domestic ones)

* CR8808 M81 (AX3000, the global version)

The difference arises from the use of different WLAN Front-End Module (FEM), which affects how you choose the OpenWrt image.

The reason why I chose OpenWrt over stock firmware is that there are many reasons. I chose OpenWrt not only for it's being open source, but also for it's being regularly updated. Many vendors have their own lifecycles, which means your device will become outdated and they will stop providing security updates after a few years.

Furthermore, you will have the freedom to choose from a variety of packages, which means high customizability. You can install more packages to fit your needs. For example, you can pick between odhcpd and dnsmasq for DNS and DHCP, or lighttpd and nginx for the web UI.

And of course, the only thing you are going to lose is time due to research, and possibly more time due to bricking your router. (I'm not kidding; you should consider how your router can be recovered to the stock firmware.)

## Preparation

* [MiWiFi RepairTools (for flashing vulnerable firmware)](https://www.miwifi.com/miwifi_download.html)

On the linked page, locate the '下载' (Download) button within the '小米路由器修复工具' (Xiaomi Router Repair Tool) section.

* Confirm your Xiaomi CR880X mainboard model

To check the mainboard model of your router, simply remove the two screws at the bottom of the device. You'll need to take a picture of the router's identification markings.

![](</images/5fa5dfc3-8afe-5afb-ac18-0251c4153a31.webp>)

Then, use a PH00 screwdriver to remove the remaining screws and open the router's casing.

![](</images/dfc0fe21-f781-551f-8dbd-ace335972715.webp>)

Here is an overview of the router's mainboard.

![](</images/bdbb69e9-5556-51e8-a4a0-634f66bda648.webp>)

On the far left side of the router's mainboard, you can see the model name. For me, it was an M79, which means I needed to use the domestic vulnerable firmware.

![](</images/c6cb073a-3901-5b1c-936d-2190633c2cd5.webp>)

* Vulnerable firmwares (Direct links):

  * AX3000 & CR8808 M81

    * [1.0.33](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/ra81/miwifi_ra81_firmware_1dd69c_1.0.33.bin)
    
    * [1.0.52](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/ra81/miwifi_ra81_firmware_release_81f29_1.0.52.bin)
    
    * [1.0.62](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/ra81/miwifi_ra81_firmware_2c953_1.0.62.bin)

    * [1.0.68](http://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/ra81/miwifi_ra81_firmware_0c1ca_1.0.68.bin)
  
  * CR8806

    * [6.2.14](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/cr8806/miwifi_cr8806_firmware_fe70b_6.2.14.bin)
    
    * [6.2.33](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/cr8806/miwifi_cr8806_firmware_4622b_6.2.33.bin)

  * CR8808 M79

    * [6.2.11](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/cr8808/miwifi_cr8808_firmware_9d216_6.2.11.bin)

    * [6.2.147](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/cr8808/miwifi_cr8808_firmware_0fbd7_6.2.147.bin)

    * [6.2.220](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/cr8808/miwifi_cr8808_firmware_a3144_6.2.220.bin)

  * CR8809

    * [6.2.102](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/cr8809/miwifi_cr8809_firmware_b814a_6.2.102.bin)
    
    * [6.2.136](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/cr8809/miwifi_cr8809_firmware_46dab_6.2.136.bin)

* OpenWrt firmware (Can be used for both mainboard models)

  * [Kernel LTS 5.15 (Dev)](https://github.com/hzyitc/openwrt-redmi-ax3000)

  * [Kernal 5.4 (Stable)](https://github.com/hzyitc/openwrt-redmi-ax3000/tree/ipq50xx-qsdk-kernel-5.4-openwrt-21.02-qsdk-11.5.05.841.1029)

  * [Kernal 4.4 (Stable)](https://github.com/hzyitc/openwrt-redmi-ax3000/tree/ipq50xx-qsdk-kernel-4.4-openwrt-21.02-qsdk-11.4.0.5.7418)

These images can be used for both mainboard models, you can doublecheck at the README.md of each repostiory. The image file name you will need to download is **openwrt-ipq50xx-arm-redmi_ax3000-squashfs-nand-factory.ubi**.

* USB-TTL Connection

You will need a USB-to-TTL board to establish a UART connection with the router. These are available at a very affordable price, typically ranging from $0.5 to $1.5 (for example, on AliExpress: https://www.aliexpress.com/w/wholesale-usb%2525252dttl.html). However, I recommend exercising caution when purchasing small and very low-cost items, particularly those under $5, from AliExpress, as you may encounter issues with package loss during shipping.

![](</images/77fa48b7-1238-520e-bb40-6b1f2ba2e931.webp>)

* [Tftpd64](https://bitbucket.org/phjounin/tftpd64/wiki/Download%20Tftpd64.md)

This will be used to send the custom image to your router.

## Firmware Reset

Look at the far right of the mainboard, where you'll find the UART connection pins. Rotate the mainboard so that **J1** is clearly visible. The pin order will then be **VCC - RX - GND - TX**.

![](</images/aca7fc3f-c3f5-5623-b966-db2812445bdd.webp>)

You can either put a male pin header and solder them for easier access.

![](</images/389638a9-93ad-5dfc-b155-2727bb59c9b6.webp>)

Before continuing, remember not to connect the VCC pin, as this could damage your mainboard. Also, ensure you swap the connections between RX and TX. For my router, I will connect the pins like this.

* GND (Red wire) to GND

* TX (Yellow wire) to RX

* RX (Orange wire) to TX

![](</images/c09f9812-66d2-5526-a043-fcb7007d6093.webp>)

![](</images/09b67e01-2c2c-505b-a5fd-e39b44593d44.webp>)

When you are ready, connect the USB-to-TTL adapter to your computer. (Do not start your router).

![](</images/e37a16b1-4ef4-51fe-b791-c97e43839af2.webp>)

On your computer, open **Device Manager** and check the **Ports (COM & LPT)** section to identify the COM port assigned to the USB-to-TTL adapter.

![](</images/9286c7bc-d3a7-53be-941c-8556045d0b62.webp>)

Use PuTTY or a similar terminal program to connect to that COM port with a speed of 115200 baud. When everything is ready, hold the Reset button and power on your router. Wait until the LED is flashing yellow and orange. This will display the router's console output in your terminal.

![](</images/affba0c3-c234-5360-8a0c-11ea7ea6992a.webp>)

Change the Ethernet interface that you will connect with the router to 192.168.31.100/24 then connect to router's LAN1 port. Your terminal will look like this.

![](</images/19bedbbc-fa2c-580b-87e8-b45aefe0efdc.webp>)

Open MiWiFi RepairTools, select the right vulnerable stock firmware then select the bottom right button.

![](</images/4a0cb198-437a-5cc3-8dc2-1372979f78c5.webp>)

You will choose which interface you connected to router's LAN1 then select the bottom right button.

![](</images/f00c3bff-19fe-5ab2-a5b3-613b3eeeabe6.webp>)

Take a look at your COM terminal. The LED will also turn blue.

![](</images/b7ccc316-d8e7-5225-a130-f09096866f22.webp>)

Power off the router and proceed to the next step.

## Getting UART

Power on the router and press any key in the COM terminal until the router boots into U-Boot, and the LED turns orange.

![](</images/9bd2b9be-0018-5a2a-ba91-38d8564c57ef.webp>)

Type these commands.

```
setenv boot_wait on
setenv uart_en 1
saveenv
```

And now you have enabled UART for your router. If you plan to install a custom image, leave the router powered on and connected via UART.

![](</images/727ee940-3d00-51e5-956f-069a1be629d8.webp>)

## Flashing OpenWrt

Start Tftpd64 and put the custom image at **Current Directory**. Keep the **Server interfaces** at 127.0.0.1.

![](</images/83a0aa48-2cee-5607-92a5-0154d386c31c.webp>)

Connect your Ethernet interface (192.168.31.100/24) to LAN1 on your router and enter the following commands:

```
# This router ip
setenv ipaddr 192.168.31.10
# TFTP server ip
setenv serverip 192.168.31.100

# Download the firmware to the RAM
tftpboot openwrt-ipq50xx-arm-redmi_ax3000-squashfs-nand-factory.ubi
```

If the image exists at the **Current Directory**, your COM terminal will display the upload progress.

![](</images/bcc43e23-f88a-502f-9691-9f32e02db0e0.webp>)

When the file upload is complete, flash the image to the router using these commands:

```
flash rootfs_1
setenv flag_try_sys2_failed 0
setenv flag_boot_rootfs 1
setenv flag_last_success 1
saveenv
reset
```

If the flashing process is successful, the LED will turn blue. Enjoy your newly flashed OpenWrt router.

![](</images/6c9adddc-1f46-5d2c-9303-1599c44f6fcd.webp>)

## Basic OpenWrt Setup

Since OpenWrt uses 192.168.1.1/24 as its default IP address, change your computer's network interface to this subnet to continue configuring OpenWrt. Exercise caution, as incorrect WAN interface configuration can lock you out of your router.

For basic setup in my homelab, I will:

* Change the router's root password: `passwd`

* As my WAN interface obtains an IP address via DHCP, I will change the LAN interface network to avoid IP address collisions:

```
uci set network.wan.proto=dhcp
uci commit
uci set network.lan.ipaddr='192.168.2.1'
uci set network.lan.netmask='255.255.255.0'
/etc/init.d/network restart
```

* Install LuCI with HTTPS support:

```
opkg update
opkg list-upgradable | cut -f 1 -d ' ' | xargs -r opkg upgrade
opkg install luci-ssl
# luci-ssl if https
/etc/init.d/uhttpd start
/etc/init.d/uhttpd enable
```

## Resources

* [Xiaomi CR880X hardware review](https://www.acwifi.net/20090.html)

* [Video guide](https://www.bilibili.com/video/BV1W94y1H71P/)

