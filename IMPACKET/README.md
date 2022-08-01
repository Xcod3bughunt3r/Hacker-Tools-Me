What is Impacket?
=================

#### Impacket adalah koleksi kelas Python untuk bekerja dengan protokol jaringan. Impacket difokuskan pada penyediaan akses terprogram tingkat rendah ke paket dan untuk beberapa protokol (misalnya NMB, SMB1-3 dan MS-DCERPC) implementasi protokol itu sendiri. Paket dapat dibangun dari awal, serta parsed dari data mentah, dan API berorientasi objek membuatnya mudah untuk bekerja dengan hierarki protokol yang dalam. Perpustakaan menyediakan seperangkat alat sebagai contoh apa yang dapat dilakukan dalam konteks perpustakaan ini.

###### Deskripsi beberapa alat dapat ditemukan di [Core Security](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket).

Protokol apa yang ditampilkan?
----------------------------

 * ##### Ethernet, Linux "Cooked" capture.
 * ##### IP, TCP, UDP, ICMP, IGMP, ARP. (IPv4 and IPv6)
 * ##### NMB and SMB1/2/3 (high-level implementations).
 * ##### DCE/RPC versions 4 and 5, over different transports: UDP (version 4 exclusively), TCP, SMB/TCP, SMB/NetBIOS and HTTP.
 * ##### Portions of the following DCE/RPC interfaces: Conv, DCOM (WMI, OAUTH),
   EPM, SAMR, SCMR, RRP, SRVSC, LSAD, LSAT, WKST, NRPC.


Getting Impacket
================

* [Trunk](https://github.com/CoreSecurity/impacket)

Setup . Quick start :
=====================

###### Raih rilis stabil terbaru, Buka kemasan dan jalankan `python setup.py install` dari direktori tempat Anda meletakkannya. Bukankah semudah itu?


Requirements
============

 * A Python interpreter. Versions 2.0.1 and newer are known to work. 
######    1. Jika Anda ingin menjalankan contoh dan Anda memiliki Python <2.7, Anda harus menginstal paket `argparse` untuk bekerja. 
######    2. Untuk dukungan Kerberos Anda akan memerlukan paket `pyasn1` 
######    3. untuk operasi kriptografi Anda akan memerlukan paket` pycrypto`
######    4. Untuk beberapa contoh Anda akan memerlukan pyopenssl (rdp_check.py) dan LDAP3 (ntlmrelayx.py) 
######    5. Jika Anda di bawah Windows, Anda akan memerlukan piradles.
 * A recent release of Impacket.

Installing
==========

###### Untuk menginstal sumber, jalankan perintah berikut dari direktori tempat distribusi Impacket telah dibongkar: `Python Setup.py Install`. Ini akan menginstal kelas ke jalur modul python default; Perhatikan bahwa Anda mungkin memerlukan izin khusus untuk menulis di sana. Untuk informasi lebih lanjut tentang perintah dan opsi apa yang tersedia dari Setup.py, jalankan `python setup.py --help-commands`.



