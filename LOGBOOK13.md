# Packet Sniffing and Spoofing Lab


This lab focus on understanding what Siniffing and Spoofing is as well as how they can be exucuted and the dangers they can cause in network communication.

## Task 1.1: Sniffing Packets

### Task 1.1 A

The objective of this task is to create a Python program for packet capturing using Scapy. We started things of by running the ifconfig command to obtain the necessary interfaces for the Python script. After that, we developed a Python script to capture and display the captured packets, utilizing the provided lab template:

```python
#!/usr/bin/python

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

interfaces = ['br-2c23230cebd7', 'enp0s3', 'lo']
pkt = sniff(iface=interfaces, filter='icmp', prn=print_pkt)
```

Upon completion, we ran the script in one container and initiated a ping to google.com in another container. Running the program with sudo permissions allowed successful packet capture.

![task1A1](/img/log13/taskA11.png)

However, doing the same thing without sudo permissions resulted in an error indicating insufficient permissions to perform the operation.

![task1A2](/img/log13/taskA12.png)

### Task 1.1 B

The objective of this task is to refine the packet capture process by implementing filters to exclude unwanted packets. This involved completing three specific tasks.

1. **Filtering ICMP Packets:**
   In the first task, we aimed to capture only ICMP packets. This was accomplished by setting the filter parameter of the sniff function to 'icmp':
   ```python
   sniff(iface=interfaces, filter='icmp', prn=print_pkt)
   ```
   Since we had already implemented this filter in the previous task, no additional action were required.

2. **Capturing Specific TCP Packets:**
   The second task involved capturing only TCP packets originating from a specific IP address (10.9.0.5) and destined for port 23. To achieve this, we adjusted the filter parameter to 'tcp && src host 10.9.0.5 && dst port 23'. The script was then ran, and in another VM, we initiated a ping to 10.9.0.5 using the command 'telnet 10.9.0.5'. The results were as follows:

   ![task1B1](/img/log13/taskB1.png)

3. **Capturing Packets from a Subnet:**
   The final task focused on capturing packets from a designated subnet, in this case, we used the subnet 128.230.0.0/16 as specified in the lab. To accomplish this, we changed the filter parameter to 'dst net 128.230.0.0/16'. Once that was done,we ran the script in one VM while pinging 128.230.0.0 from another VM. Obtained the following  results:

   ![task1B2](/img/log13/taskB2.png)



## Task 1.2: Spoofing ICMP Packets

The objective of this task is to simulate ICMP echo request packets using Scapy for the purpose of packet spoofing. To accomplish this, we created the following Python script, which sends ICMP packets to our VM ('10.9.0.6') from an arbitrary source, in this case, '8.8.8.8':

```python
from scapy.all import *

a = IP()
a.src='8.8.8.8'
a.dst='10.9.0.6'
b=ICMP()
p = a/b
send(p)
```

Once that was finished, we initiated a Wireshark capture in our VM and ran the Python script in another VM:

![task2](/img/log13/task21.png)
![task2](/img/log13/task22.png)

After analising the results we concluded that the VM successfully received and accepted the packets sent by us.


## Task 1.3: Traceroute

The goal of this task is to create a script using Scapy to determine the distance, measured in terms of the number of routers, between the VM and a designated destination. For this purpose, we created the following Python script:

```python
from scapy.all import *

a = IP()
a.dst='8.8.4.4'

i = 1
reached = False

while (not reached):
    
    a.ttl = i
    response=sr1(a/ICMP(), timeout = 7, verbose = 0)
    
    if response is None:
        print(f"{i} Requested Timed Out")
    elif response.type == 0:
        print(f"{i} {response.src}")
        reached = True
    else:
        print(f"{i} {response.src}")
        
    i += 1
```

The program uses an automated approach to address the problem, eliminating the need to manually specify the Time-To-Live (TTL). For our testing, we selected the IP address '8.8.4.4' as the destination and ran the script, obatining the following results:

![task3](/img/log13/task3.png)

We can observe that it took 12 hops to reach the destination.



## Task 1.4: Sniffing and-then-Spoofing

The objective of this task is to integrate both sniffing and spoofing techniques into a single program, creating a sniff-and-then-spoof application. The purpose is to capture packets sent by the user container , and subsequently, send responses to the user container. To achieve this, we developed the following Python script:

```python
#!/usr/bin/python
from scapy.all import *

def spoof(pkt):
    if(pkt[2].type == 8):
        a = IP()
        a.src = pkt[1].dst
        a.dst = pkt[1].src
        
        id = pkt[2].id
        seq = pkt[2].seq
        load = pkt[3].load
        
        reply = a/ICMP(type=0, id=id, seq=seq)/load
        
        send(reply, verbose=0)

interfaces=['br-2c23230cebd7','enp0s3', 'lo'] 
sniff(iface=interfaces, filter='icmp', prn=spoof)
```

The script captures a packet, identifies if it is an echo request, and, if so, generates a response based on the request information, sending it back to the source. In our testing, we were asked to ping three different machines and analyze the results.

1. **Machine: 1.2.3.4 (Non-Existing Host on the Internet):**

We started by conducting a Wireshark capture in the user VMs. After that we pinged 1.2.3.4 from the user VM without running the Python script.
![task41](/img/log13/task411.png)
![task41](/img/log13/task412.png)
No response was observed, which is expected as the host does not exist. After that we repeated the ping to 1.2.3.4, this time running the script in the attacker VM.
![task42](/img/log13/task421.png)


We can observe that packets were received and accepted, demonstrating successful sniffing and spoofing.

2. **Machine: 10.9.0.99 (Non-Existing Host on the LAN):**

We repeated the process with the non-existing host on the LAN (10.9.0.99).
![task43](/img/log13/task43.png)
![task44](/img/log13/task44.png)
In both situations, the destination was unreachable. This is because the user VM lacks information on how to reach the destination in the ARP table. Consequently, even with the script running, no packets passed the sniffing filters, resulting in no packets being sent.

3. **Machine: 8.8.8.8 (Existing Host on the Internet):**

Repeated the same process with an existing host on the Internet (8.8.8.8).

![task45](/img/log13/task451.png)
![task45](/img/log13/task452.png)
![task46](/img/log13/task461.png)
![task46](/img/log13/task462.png)
Requests were received in both scenarios. The only difference was that, when the script was running, repeated packets were received and detected by the user machine.

