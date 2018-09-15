Honeycomb

A project based on Honeyd plugin Honeycomb to create signatures from pcaps

1.Installation

1) Libstree
This project requires Libstree , download it here:http://www.icir.org/christian/downloads/libstree-0.4.2.tar.gz
unzip and enter directory "libstree-0.4.2"and execute:

./configure
make 
sudo make install

for more info refer to http://www.icir.org/christian/libstree/

2) Other dependencies

Libevent >=1.1,Honeyd >=0.7

2.Usage

honeycomb <pcap directory>
  
P.S: bugs in hc_string_alg_lcs():
*** Error in `honeycomb': munmap_chunk(): invalid pointer: 0x00007ffc3ffd5210 ***

unsolved...
