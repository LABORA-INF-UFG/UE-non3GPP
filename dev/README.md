# UE-non3GPP
User Equipment for non-3GPP access via N3IWF | Working in-progress

### Environment
The content described in this repository was tested in [Digital Occean](https://www.digitalocean.com/) cloud environment. 1º VM where free5GC will run (except N3IWF) and 2º VM where the N3IWF, each of them with the following configurations:
* SO: Ubuntu 20.04 (LTS) x64
* Uname -r: 5.4.0-122-generic
* Memory: 4 GB
* Disk: 80 GB

#### Before starting
The development environment setup is exec by Ansible. Before starting it is necessary to access via SSH each one of the VM's and execute the following command to install some basic dependencies.
```
sudo apt update && apt -y install python && sudo apt -y install git && sudo apt -y install ansible && sudo apt -y install net-tools
```

### Dev Environment Setup
Clone the project with the following command:
```
apt update && git clone https://github.com/LABORA-INF-UFG/UE-non3GPP.git 
```

After cloning the project, you need to edit the **hosts** file, located in the _UE-non3GPP/dev/free5gc-v3.1.1_ . The __host__ file contains 3 mapped hosts (fee5gc-core, fee5gc-n3iwf and labora-UE-non3GPP). Let's configure _fee5gc-core_ and _fee5gc-n3iwf_. The _labora-UE-non3GPP_ host is used to deploy a UE version on a 3rd machine (considering for example a case where the operator's machine does not have access to the _fee5gc-core_ and _fee5gc-n3iwf_ VMs).
Let's assume that the operator's machine has full access to the _fee5gc-core_ and _fee5gc-n3iwf_ machines and is not behind **NAT**.

Let's start with the settings of the host responsible for running _fee5gc-core_.
* Replace the 1º marker ```<IP-address>```, illustrated in the following figure in red color, with the IP address of the VM where _fee5gc-core_ will be configured.
<p align="center">
    <img src="../images/ip_free5gc_hosts.png"/> 
</p>

* Access the VM _fee5gc-core_, run ```ifconfig``` and get the name of **internet network interface**, like as illustrated in the figure below:
<p align="center">
    <img src="images/if_config.png"/> 
</p>
replace the 2º marker ```<internet-network-interface>```, illustrated in the following figure in red color, with the name of the network interface that provides internet access.
<p align="center">
    <img src="images/ip_free5gc_hosts.png"/> 
</p>
Obs: Keep n3iwf_install parameter with value FALSE for host _fee5gc-core_

* Replace the 3º marker ```<IP-address>```, illustrated in the following figure in yellow color, with the IP address of the VM where _fee5gc-n3iwf_ will be configured.
* Replace the 4º marker ```<free5gc-core-IP-address>```, illustrated in the following figure in yellow color, with the IP address of the VM where _fee5gc-core_ will be configured (the same IP address informed in the 1st marker).
<p align="center">
    <img src="images/ip_free5gc_hosts.png"/> 
</p>

#### SSH Key exchange
To configure the _fee5gc-core_ and _fee5gc-n3iwf_ it is necessary that the machine has root access. This is done through an SSH key exchange, as described in the following:
* Generate SSH Key:
```
ssh-keygen -t ecdsa -b 521
```
obs: after executing the command, press ENTER 3x.

* After generating the key, let's copy it to each of the VMs.:
```
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<free5gc-ip-address>
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<n3iwf-ip-address>
```

### Test Ansible Connection
Now let's test the Ansible connection with the respective hosts configured in the previous steps. In the terminal, inside the ```UE-non3GPP/dev_environment_setup``` directory, run the following command:
```
ansible -i ./hosts -m ping all -u root
```

### Go Install with Ansible
The command below installs GO v.1.14 on each of VMs
```
ansible-playbook dev/free5gc-v3.1.1/go-install.yaml -i dev/free5gc-v3.1.1/hosts
```
Now it is necessary to access each of the VMs and update bashrc
```
source ~/.bashrc
```

### Setup Free5GC and N3IWF with Ansible
Now let's run the script responsible for configuring free5gc (except the N3IWF network function) and a version of free5gc containing only the N3IWF network function
```
ansible-playbook dev/free5gc-v3.1.1/free5gc-n3iwf-setup.yaml -i dev/free5gc-v3.1.1/hosts
```

### Setup UE-non3GPP with Ansible
ansible-playbook dev/UEnon3GPP.yaml -i dev/free5gc-v3.1.1/hosts

### Start Free5GC and N3IWF
TODO

### Register UE-non3GPP into Free5GC
TODO

### Config UE-non3GPP
TODO

### Start UE-non3GPP
TODO
