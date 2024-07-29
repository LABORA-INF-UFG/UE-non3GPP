# UE-non3GPP
User Equipment for non-3GPP access via N3IWF | Working in-progress

### Environment
The content described in this repository was tested in [Digital Occean](https://www.digitalocean.com/) cloud environment. 1º VM where Open5GS will run and 2º VM where the Free5GS N3IWF, each of them with the following configurations:
* SO: Ubuntu 20.04 (LTS) x64
* Uname -r: 5.4.0-122-generic
* Memory: 4 GB
* Disk: 80 GB

#### Before starting
The development environment setup is exec by Ansible. Before starting it is necessary to access via SSH each one of the VM's and execute the following command to install some basic dependencies.
```
sudo apt update && apt -y install python && sudo apt -y install git && sudo apt -y install ansible && sudo apt -y install net-tools && sudo apt -y install traceroute wireless-tools
```

### Dev Environment Setup
Clone the project with the following command:
```
apt update && git clone https://github.com/LABORA-INF-UFG/UE-non3GPP.git 
```

After cloning the project, you need to edit the **hosts** file, located in the _UE-non3GPP/dev/free5gc-v3.1.1_ . The __host__ file contains 3 mapped hosts (fee5gc-core, fee5gc-n3iwf and labora-UE-non3GPP). Let's configure _open5gs-core_ and _fee5gc-n3iwf_. The _labora-UE-non3GPP_ host is used to deploy a UE version on a 3rd machine (considering for example a case where the operator's machine does not have access to the _open5gs-core_ and _fee5gc-n3iwf_ VMs).
Let's assume that the operator's machine has full access to the _open5gs-core_ and _fee5gc-n3iwf_ machines and is not behind **NAT**.

Let's start with the settings of the host file replace the markers illustrated in the following figure:
<p align="center">
    <img src="../../images/ip_open5gs_hosts.png"/> 
</p>

* Replace all the markers ```<<Open5GS-ip-addr>> ```, with the IP address of the VM where _open5gs-core_ will be configured.
* Replace all the markers ```<<free5gs-n3iwf-ip-addr>>```, with the IP address of the VM where _fee5gc-n3iwf_ will be configured.
* Replace the marker ```<<UEnon3GPP-ip-addr>>```, with the IP address of the VM where _UE-non3GPP_ will be configured.

#### SSH Key exchange
To configure the _fee5gc-core_ and _fee5gc-n3iwf_ it is necessary that the machine has root access. This is done through an SSH key exchange, as described in the following:
* Generate SSH Key:
```
ssh-keygen -t ecdsa -b 521
```
obs: after executing the command, press ENTER 3x.

* After generating the key, let's copy it to each of the VMs.:
```
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<open5gs-ip-addr>
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<n3iwf-ip-addr>
ssh-copy-id -i ~/.ssh/id_ecdsa.pub root@<ue-non3GPP-ip-addr>
```

### Test Ansible Connection
Now let's test the Ansible connection with the respective hosts configured in the previous steps. In the terminal, inside the ```UE-non3GPP/dev``` directory, run the following command:
```
ansible -i ./dev/open5gs/hosts -m ping all -u root
```

### Go Install with Ansible
The command below installs GO v.1.14 on each of VMs. The following description assumes running the command from the project root dir (UE-non3GPP).

#### Free5gc N3IWF - Go Version 1.14
```
ansible-playbook dev/open5gs/go-install-1.14.yaml -i dev/open5gs/hosts
```
Now it is necessary to access each of the VMs and update bashrc
```
source ~/.bashrc
```

#### UE-non3GPP - Go Version 1.21
```
ansible-playbook dev/open5gs/go-install-1.21.yaml -i dev/open5gs/hosts
```
Now it is necessary to access each of the VMs and update bashrc
```
source ~/.bashrc
```

### Open5GS and N3IWF Setup with Ansible
Now let's run the script responsible for configuring open5gs and a version of free5gc containing only the N3IWF network function. The following description assumes running the command from the project root dir (UE-non3GPP).
#### Open5GS Setup
```
ansible-playbook dev/open5gs/open5gs-setup.yaml -i dev/open5gs/hosts 
```
#### N3IWF Setup
```
ansible-playbook dev/open5gs/n3iwf-setup.yaml -i dev/open5gs/hosts
```

### Setup UE-non3GPP with Ansible
```
ansible-playbook dev/open5gs/ue-non3GPP-setup.yaml -i dev/open5gs/hosts
```

### Start Open5GS
After performing the Open5GS, N3IWF and UE-non3gpp installation, the next step is to initialize the Free5gc network functions. To do this it is necessary to access the VM where Free5gc was deployed in two different terminals, the first will be used to initialize the network functions and the second to initialize the API that provides access to MongoDB.

### Init N3IWF
Initializing N3WIF is similar to the process performed when initializing free5GC, however, only 1 terminal will be required. Access the VM where N3IWF was installed and navigate to the ```/root/go/src/free5gc/NFs/n3iwf``` directory. After accessing the directory, run the following command ```go run cmd/main.go```.  On the first run, some dependencies will be configured and after a few seconds a Log message similar to ```[INFO][N3IWF][Init] N3IWF running...``` will be displayed. It indicates that the N3IWF is ready and properly connecting to the previously initialized Free5gc.

### Config UE-non3GPP
The UE configuration parameters are contained in the ```~/go/src/UE-non3GPP/config/config.yaml```. Using the installation process described in this repository, all parameters were properly configured in an automated way, so that no adjustments to the configuration file were necessary.

### Start UE-non3GPP
The final step is to initialize the UE-non3GPP so that the control and data tunnels are configured through the N3IWF. To do this, access the VM where the UE-non3GPP was installed and go to the ```~/go/src/UE-non3GPP``` directory and run the following command: ```go run cmd/main.go ue```. After configuring some dependencies, the connection with N3IWF will be properly established and two network interfaces will be created, the first of type ```ipsec``` and the second named ```gretun1```. To test the operation, simply run a PING test through the ```gretun1``` interface with the following command: ```ping -I gretun1 8.8.8.8```.

## Verificações pos instalação
Após a instalação algumas verificações devem se feitas.

### Verificar se o UE foi registrado no Mongo
Para verificar acesse a VM do open5gs e execute os comandos abaixo:
```
mongo
use open5gs
db.subscribers.find().pretty()
```

### Monitorar Logs AMF
Antes de inicializar a N3IWF deve-se fazer um tail no log da AMF. Os logs do open5gs estão em ```/root/open5gs/install/var/log/open5gs```
```
tail -f /root/open5gs/install/var/log/open5gs/amf.log
```

Tem um erro no registro do UE na AMF

