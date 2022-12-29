# UE-non3GPP
User Equipment for non-3GPP access via N3IWF | Working in-progress

#### Environment
The content described in this repository was tested on a VM in the [Digital Occean](https://www.digitalocean.com/) cloud environment with the following configurations:
* SO: Ubuntu 20.04 (LTS) x64
* Uname -r: 5.4.0-122-generic
* Memory: 8 GB
* Disk: 80 GB

#### Dev Environment Setup
The development environment setup is exec by Ansible and involves 3 virtual machines: (i) VM representing UE-non3GPP, (ii) VM where free5GC will run (except N3IWF) and (iii) VM where the N3IWF. 

##### UE-non3GPP VM Config
After creating the VM, access via SSH and clone the project with the following command:
```
git clone https://github.com/LABORA-INF-UFG/UE-non3GPP.git 
```



