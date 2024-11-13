#!/bin/bash

# Add non free sources for snmp
cat <<'END' | sudo tee /etc/apt/sources.list.d/frr.list
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian/ bookworm contrib non-free non-free-firmware
deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian/ bookworm contrib non-free non-free-firmware

deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://security.debian.org/debian-security bookworm-security contrib non-free non-free-firmware
deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://security.debian.org/debian-security bookworm-security contrib non-free non-free-firmware

deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian/ bookworm-updates contrib non-free non-free-firmware
deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian/ bookworm-updates contrib non-free non-free-firmware
END

sudo apt-get update

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    gdb \
    iproute2 \
    net-tools \
    python3-pip \
    iputils-ping \
    tshark \
    valgrind \
    tmux \
    iperf \
    libsnmp-dev \
    snmpd \
    snmp \
    snmp-mibs-downloader

sudo python3 -m pip install wheel --break-system-packages
sudo python3 -m pip install 'pytest>=8.3.2' 'pytest-asyncio>=0.24.0' 'pytest-xdist>=3.6.1' --break-system-packages
sudo python3 -m pip install 'scapy>=2.4.5' --break-system-packages
sudo python3 -m pip install xmltodict --break-system-packages
sudo python3 -m pip install git+https://github.com/Exa-Networks/exabgp@0659057837cd6c6351579e9f0fa47e9fb7de7311 --break-system-packages
sudo python3 -m pip install 'protobuf>=4' --break-system-packages

sudo useradd -d /var/run/exabgp/ -s /bin/false exabgp

cat <<'END' | sudo tee /etc/security/limits.conf
#<domain>      <type>  <item>         <value>
*               soft    core          unlimited
root            soft    core          unlimited
*               hard    core          unlimited
root            hard    core          unlimited
END

sudo download-mibs

sudo wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/iana/IANA-IPPM-METRICS-REGISTRY-MIB -O /usr/share/snmp/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB
sudo wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU -O /usr/share/snmp/mibs/ietf/SNMPv2-PDU
sudo wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/IPATM-IPMC-MIB -O /usr/share/snmp/mibs/ietf/IPATM-IPMC-MIB

cat <<'END' | sudo tee /etc/snmp/snmp.conf
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
mibs +ALL
END

echo "alias ls='ls --color=auto -lh'" >> ~/.bashrc
echo "alias make='make -j'" >> ~/.bashrc
echo "alias topotest='sudo -E pytest -s -v -nauto --dist=loadfile'" >> ~/.bashrc
echo "alias topology='sudo -E pytest -s --topology-only'" >> ~/.bashrc

echo -e " \n\
if [ -f /usr/share/bash-completion/completions/git ]; then\n\
  . /usr/share/bash-completion/completions/git\n\
fi\n" >> ~/.bashrc

# This is needed as of 9/9/2024 to get address sanitizer to work properly, without it, it prints an error in zebra.err in a loop until disk space runs out
sudo sysctl vm.mmap_rnd_bits=28
