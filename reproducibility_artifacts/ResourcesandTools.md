# Resources and Tools Required
* Heat template for controller:     
    Included: ctrl_template.yml
* Obtain AL2S circuits between TACC and UC and create network.

* Connect instances to network created above.

* Server - Apache2 HTTP/2
    * Install from source
    
        Dependencies: libapr1-dev, libaprutil1-dev and nghttp2

        ```sudo wget https://github.com/nghttp2/nghttp2/releases/download/v1.32.0/nghttp2-1.32.0.tar.gz```
    * Edit config file (/usr/local/apache2/conf/httpd.conf)
        ```
       LoadModule http2_module modules/mod_http2.so
       Protocols h2 h2c http/1.1
       ```
    * Tune for TCP
        ```
        sudo ethtool -K <interface> rx off tx off sg off tso off ufo off gso off gro off lro off rxvlan off txvlan off rxhash off
        
        ```
    * Run
    ```sudo /usr/local/apache2/bin/apachectl start```
   
        BigBuckBunny dataset - http://www-itec.uni-klu.ac.at/ftp/datasets/DASHDataset2014/BigBuckBunny/2sec/

* Cross Traffic - Iperf3

```iperf3 -c <server_ip> -t 20 -i 5 -b 900Mbps -u -t 500```
* Controller - RYU OpenFlow
    
    Included: simple_switch_13_custom_chameleon_org.py
* P4 Setup - Download and Execute the following script to setup BMV2 switch for P4:
Compile this P4 file for HTTP/2 header differentiation. Note that hyper assigns Stream IDs as follows: 1,3,5 etc., which means retransmissions are assigned a Stream ID of 3 while original transmissions are assigned a Stream ID of 1.
    * Compile: 
    ```sudo p4c --target bmv2 --arch v1model solution/basic.p4```
    * Create 4 VLAN interfaces with 802.1Q tag. Note that one tag is reserved for the host network while the others will    be assigned to Stream IDs
    ```
        sudo vconfig add <if_name> <vlan_id>
        sudo vconfig <if_name.vlan_id> up
        ```
    * Run:
    ```sudo simple_switch -i 1@eno1.103 -i 2@eno1.202 -i 3@eno1.203 -i 4@eno1.204 /home/cc/tutorials/exercises/basic/basic.json```
* Client - Install Python hyper HTTP/2 (https://hyper.readthedocs.io/en/latest/)
    * Run: ```taskset 0x00000001 python3 download_test_http2.py```
    
        Note: taskset is used to assign execution to a single core since there are some perfomance issues with the hyper library and multi-core.
