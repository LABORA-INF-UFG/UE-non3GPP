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

Let's start with the settings of the host responsible for running __fee5gc-core__.
* Replace the marker ```<IP-address>``` with the IP address of the VM where __fee5gc-core__ will be configured as shown in the figure below.
<p align="center">
    <img src="images/ip_free5gc_hosts.png"/> 
</p>

* Access the VM __fee5gc-core__, run ```ifconfig``` and get the name of **internet network interface**, like as illustrated in the figure below:
<p align="center">
    <img src="images/if_config.png"/> 
</p>
replace the ```<internet-network-interface>``` tag with the name of the network interface that provides internet access, as illustrated below:
<p align="center">
    <img src="images/net_interface_name_free5gc_hosts.png"/> 
</p>
Obs: Keep n3iwf_install parameter with value FALSE for host __fee5gc-core__

Now let's configure the N3IWF installation parameters. Still in the hosts file, but now in ```[fee5gc-n3iwf]```; replace the ```<IP-address>``` marker with the IP address of the machine where the N3IWF will be executed (highlighted in yellow in the following figure) and the ```<IP-address-free5gc>``` marker with the IP address of the machine where free5gc was configured (same IP address informed in the ```<IP-address>``` parameter of the host ```[fee5gc-core]``` in the line above).
<p align="center">
    <img src="images/ip_n3iwf_hosts.png"/> 
</p>


To configure the 3 VMs it is necessary that the machine has root access. This is done through an SSH key exchange, as described in the following steps:
* Generate SSH Key:
```
ssh-keygen -t ecdsa -b 521
```
obs: after executing the command, press ENTER 3x.

* After generating the key, let's copy it to each of the VMs.:
```
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<free5gc-ip-address>
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<n3iwf-ip-address>
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<UE-non3GPP-ip-address>
```

## UE-non3GPP VM Config




### Test Ansible Connection
Now let's test the Ansible connection with the respective hosts configured in the previous steps. In the terminal, inside the ```UE-non3GPP/dev_environment_setup``` directory, run the following command:
```
ansible -i ./hosts -m ping all -u root
```

### Go Install eith Ansible
The command below installs GO v.1.14 on each of VMs
```
ansible-playbook dev_environment_setup/<<dir-version-free5gc>>/go-install.yaml -i dev_environment_setup/<<dir-version-free5gc>>/hosts
```
Now it is necessary to access each of the VMs and update bashrc
```
source ~/.bashrc
```

### Run Ansible Free5GC and N3IWF Setup
Now let's run the script responsible for configuring free5gc (except the N3IWF network function) and a version of free5gc containing only the N3IWF network function
```
ansible-playbook dev_environment_setup/<<dir-version-free5gc>>/free5gc-n3iwf-setup.yaml -i dev_environment_setup/<<dir-version-free5gc>>/hosts
```

### Run Ansible UE-non3GPP Setup
Now let's run the script that configures the UE-non3GPP code, with all the interconnection configuration with the other 2 VMs
```
ansible-playbook dev_environment_setup/UEnon3GPP-setup.yaml -i dev_environment_setup/<<dir-version-free5gc>>/hosts
```