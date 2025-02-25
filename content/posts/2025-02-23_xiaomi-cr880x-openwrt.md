---
title: "OpenWrt on Xiaomi CR880x & AX3000"
date: 2025-02-23T19:00:00+07:00
draft: true
lastmod: 
showLastmod: false
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

* OpenWrt firmware

  * Kernel 5.15 (Dev)

  * Kernal 5.4 (Stable)

  * Kernal 4.4 (Stable)

* USB-TTL Connection

You will need a USB-to-TTL board to establish a UART connection with the router. These are available at a very affordable price, typically ranging from $0.5 to $1.5 (for example, on AliExpress: https://www.aliexpress.com/w/wholesale-usb%2525252dttl.html). However, I recommend exercising caution when purchasing small and very low-cost items, particularly those under $5, from AliExpress, as you may encounter issues with package loss during shipping.

![](</images/77fa48b7-1238-520e-bb40-6b1f2ba2e931.webp>)

## Firmware Reset

## Getting UART

## Flashing OpenWrt

## Basic OpenWrt Setup

## Resources

* [Xiaomi CR880X hardware review](https://www.acwifi.net/20090.html)

* [Video guide](https://www.bilibili.com/video/BV1W94y1H71P/)

