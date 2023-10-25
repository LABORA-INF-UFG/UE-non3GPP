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
sudo apt update && apt -y install python && sudo apt -y install git && sudo apt -y install ansible && sudo apt -y install net-tools && sudo apt -y install traceroute
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
    <img src="../images/if_config.png"/> 
</p>
replace the 2º marker ```<internet-network-interface>```, illustrated in the following figure in red color, with the name of the network interface that provides internet access.
<p align="center">
    <img src="../images/ip_free5gc_hosts.png"/> 
</p>
Obs: Keep n3iwf_install parameter with value FALSE for host _fee5gc-core_

* Replace the 3º marker ```<IP-address>```, illustrated in the following figure in yellow color, with the IP address of the VM where _fee5gc-n3iwf_ will be configured.
* Replace the 4º marker ```<free5gc-core-IP-address>```, illustrated in the following figure in yellow color, with the IP address of the VM where _fee5gc-core_ will be configured (the same IP address informed in the 1st marker).
<p align="center">
    <img src="../images/ip_free5gc_hosts.png"/> 
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
Now let's test the Ansible connection with the respective hosts configured in the previous steps. In the terminal, inside the ```UE-non3GPP/dev``` directory, run the following command:
```
ansible -i ./dev/free5gc-v3.1.1/hosts -m ping all -u root
```

### Go Install with Ansible
The command below installs GO v.1.14 on each of VMs. The following description assumes running the command from the project root dir (UE-non3GPP).

#### Free5gc and N3IWF - Go Version 1.14
```
ansible-playbook dev/free5gc-v3.1.1/go-install-1.14.yaml -i dev/free5gc-v3.1.1/hosts
```
Now it is necessary to access each of the VMs and update bashrc
```
source ~/.bashrc
```

#### UE-non3GPP - Go Version 1.21
```
ansible-playbook dev/free5gc-v3.1.1/go-install-1.21.yaml -i dev/free5gc-v3.1.1/hosts
```
Now it is necessary to access each of the VMs and update bashrc
```
source ~/.bashrc
```

### Free5GC and N3IWF Setup with Ansible
Now let's run the script responsible for configuring free5gc (except the N3IWF network function) and a version of free5gc containing only the N3IWF network function. The following description assumes running the command from the project root dir (UE-non3GPP).
#### Free5GC Setup
```
ansible-playbook dev/free5gc-v3.1.1/free5gc-setup.yaml -i dev/free5gc-v3.1.1/hosts -e  "internet_network_interface=<< internet network interface name>>"
```
#### N3IWF Setup
```
ansible-playbook dev/free5gc-v3.1.1/n3iwf-setup.yaml -i dev/free5gc-v3.1.1/hosts
```

### Setup UE-non3GPP with Ansible
```
ansible-playbook dev/UEnon3GPP-setup.yaml -i dev/free5gc-v3.1.1/hosts
```

### Start Free5GC
After performing the Free5gc, N3IWF and UE-non3gpp installation, the next step is to initialize the Free5gc network functions. To do this it is necessary to access the VM where Free5gc was deployed in two different terminals, the first will be used to initialize the network functions and the second to initialize the API that provides access to MongoDB.

#### Init Free5GC Network Functions
Using the first terminal connected to the VM where Free5gc was installed, go to the ```/root/go/src/free5gc``` dir. First of all it is necessary to compile the Free5gc network functions. Run the command ```make``` and wait a few seconds, the process takes a little time. After compiling the project (it is hoped that no errors occurred during the compilation process) we will initialize the network functions using the ```run.sh``` script. It may be necessary to assign additional permission to run the script, this can be done using the command ```chmod 777 -R ./run.sh```. After assigning permission, initialize the Free5gc network functions through the following command ```./run.sh```. The terminal will be linked to the execution process, reproducing the log messages from the network functions as each function executes its responsibilities.

#### Init Free5GC API
Using the second terminal, we will now initialize the API that provides access to MongoDB registration end-points. In the terminal, access the ```/root/go/src/free5gc/webconsole``` directory and then run the following command ```go run server.go```. After a few seconds, a Log message equivalent to this ```Listening and serving HTTP on :5000```.

### Init N3IWF
Initializing N3WIF is similar to the process performed when initializing free5GC, however, only 1 terminal will be required. Access the VM where N3IWF was installed and navigate to the ```/root/go/src/free5gc/NFs/n3iwf``` directory. After accessing the directory, run the following command ```go run cmd/main.go```.  On the first run, some dependencies will be configured and after a few seconds a Log message similar to ```[INFO][N3IWF][Init] N3IWF running...``` will be displayed. It indicates that the N3IWF is ready and properly connecting to the previously initialized Free5gc.

### Register UE-non3GPP into Free5GC
With the Free5gc network functions initialized and the MongoDB access API responding on port 5000 of the VM where the Free5GC is located, the next step is to register the UE in the database. To do this, access the VM where the UE was installed and go to the ```~/go/src/UE-non3GPP/dev``` directory. Using the ```ls``` command you can verify that a file called ```include_ue_non3GPP.sh``` was created in this directory. This is a script that, using the ```curl``` command, makes a call to the Free5GC API with the aim of adding a UE containing the same parameters already inserted in the ```~/go/src/UE-non3GPP/config/config.yaml``` configuration file. You will probably need to assign additional permission to run the ```include_ue_non3GPP.sh``` file, this can be done using the following command ```chmod 777 -R ./include_ue_non3GPP.sh```. After assigning permission, simply run the script with the following command ```./include_ue_non3GPP.sh```. As a result, a pair of keys indicating an empty ```JSON``` object will be printed in the LOG like this ```{}```, everything is fine!. Additionally you can check the Free5GC terminal where the API was initialized, you will be able to observe LOG messages indicating the UE registration. If an error message with text similar to ```PostSubscriberByID err: RestfulAPIPostMany err: must provide at least one element in input slice``` has been displayed on the respective terminal, you can disregard it, everything is as expected!

### Config UE-non3GPP
The UE configuration parameters are contained in the ```~/go/src/UE-non3GPP/config/config.yaml```. Using the installation process described in this repository, all parameters were properly configured in an automated way, so that no adjustments to the configuration file were necessary.

### Start UE-non3GPP
The final step is to initialize the UE-non3GPP so that the control and data tunnels are configured through the N3IWF. To do this, access the VM where the UE-non3GPP was installed and go to the ```~/go/src/UE-non3GPP``` directory and run the following command: ```go run cmd/main.go ue```. After configuring some dependencies, the connection with N3IWF will be properly established and two network interfaces will be created, the first of type ```ipsec``` and the second named ```gretun1```. To test the operation, simply run a PING test through the ```gretun1``` interface with the following command: ```ping -I gretun1 8.8.8.8```.
