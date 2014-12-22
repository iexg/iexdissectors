# IEX Dissectors

This module contains a set of wireshark dissectors for the IEX proprietary protocols. They are intended to be built based on the Wireshark packages provided by Ubuntu 14.10+ and Fedora 21+.

## What it is

As of the time of writing, this plugin will decode the [IEX TOPS market data feed][http://www.iextrading.com/docs/IEX+TOPS+Spec.pdf] as seen within the [IEX Transport Protocol][http://iextrading.com/docs/IEX+Transport+Spec.pdf]. Here's an example of a tshark (console) decode of sample (make believe) data:

![Example TOPS Decode](https://raw.githubusercontent.com/iexg/iexdissectors/master/docs/sshot1.jpg)

```
Frame 1: 346 bytes on wire (2768 bits), 346 bytes captured (2768 bits)
Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)
Internet Protocol Version 4, Src: 127.0.0.1 (127.0.0.1), Dst: 127.0.0.1 (127.0.0.1)
User Datagram Protocol, Src Port: 16641 (16641), Dst Port: 16641 (16641)
IEX Transport Protocol
    Version: 1
    Message Protocol: IEX-TOPS
    Channel ID: 1
    Session ID: 1074790400
    Length: 264
    Count: 6
    Offset: 0
    First Message Sequence Number: 1
    Send Time: Nov 26, 2014 20:56:12.292558382 UTC
    Quote Message
        Message Length: 42
        Message Type: Quote (81)
        0100 0000 = Flags: 0x40
        0... .... = Halted: No
        .1.. .... = Pre/Post-Market: Yes
        Time: Nov 26, 2014 20:56:12.075416239 UTC
        Symbol: C       
        Bid Size: 700
        Bid Price: 49.09800
        Ask Price: 0.00000
        Ask Size: 0
    Quote Message
        Message Length: 42
        Message Type: Quote (81)
        0100 0000 = Flags: 0x40
        0... .... = Halted: No
        .1.. .... = Pre/Post-Market: Yes
        Time: Nov 26, 2014 20:56:12.116824487 UTC
        Symbol: C       
        Bid Size: 600
        Bid Price: 49.09800
        Ask Price: 0.00000
        Ask Size: 0
    Quote Message
        Message Length: 42
        Message Type: Quote (81)
        0100 0000 = Flags: 0x40
        0... .... = Halted: No
        .1.. .... = Pre/Post-Market: Yes
        Time: Nov 26, 2014 20:56:12.123097719 UTC
        Symbol: MSFT    
        Bid Size: 0
        Bid Price: 0.00000
        Ask Price: 38.01600
        Ask Size: 1100
    Quote Message
        Message Length: 42
        Message Type: Quote (81)
        0100 0000 = Flags: 0x40
        0... .... = Halted: No
        .1.. .... = Pre/Post-Market: Yes
        Time: Nov 26, 2014 20:56:12.128195659 UTC
        Symbol: WOOF    
        Bid Size: 900
        Bid Price: 28.06100
        Ask Price: 0.00000
        Ask Size: 0
    Quote Message
        Message Length: 42
        Message Type: Quote (81)
        0100 0000 = Flags: 0x40
        0... .... = Halted: No
        .1.. .... = Pre/Post-Market: Yes
        Time: Nov 26, 2014 20:56:12.274243178 UTC
        Symbol: MSFT    
        Bid Size: 0
        Bid Price: 0.00000
        Ask Price: 38.01600
        Ask Size: 900
    Quote Message
        Message Length: 42
        Message Type: Quote (81)
        0100 0000 = Flags: 0x40
        0... .... = Halted: No
        .1.. .... = Pre/Post-Market: Yes
        Time: Nov 26, 2014 20:56:12.292558382 UTC
        Symbol: QQQ     
        Bid Size: 0
        Bid Price: 0.00000
        Ask Price: 83.05800
        Ask Size: 1700

```

## Installing

The first step is to make sure you're using Fedora 21 or Ubuntu 14.10 or later, and have the appropriate header packages installed. On Fedora, you'll get everything you need with:

```
sudo yum -y install wireshark-devel
```

On Ubuntu, you'll need to install the libwireshark-dev package:

```
sudo apt-get install libwireshark-dev
```

From there, you'll need to clone this repository, go into the directory, and build it:

```
git clone https://github.com/iexg/iexdissectors.git
cd iexdissectors
autoreconf -fi
./configure --prefix=/usr --localstatedir=/var/lib --sysconfdir=/etc --with-dissector-dir=/home/${USER}/.wireshark/plugins
make
make install
```

Assuming you are using the supported distros and have everything installed, it should 

### Other Environments

If you want to build the dissectors on another Linux distro, that distro needs to provide three things for this to work:

1. Wireshark 1.12.1
1. The wireshark headers installed in a reasonable place (e.g. /usr/include/wireshark)
1. A pkg-config file with the correct include path and libs

One other thing to note is that Wirehsark doesn't install headers by default when built from source, the -dev* package and it's pkg-config file are niceties added by distros.

### Windows, MacOS X

I don't have any Windows or Macs to test this on, so I haven't made any effort to make this go on anything but Linux with the latest (as of the time I wrote this) wireshark, so it won't work out of the box. That said, I'm not doing anything crazy, or outside the existing C standard with a 2.x libglib, so it should build OK assuming you've got it integrated.

If you do hack this to work on another OS, please take the extra couple minutes to send me the patch so other people can appreciate your efforts.
