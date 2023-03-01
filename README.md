# UE-non3GPP
User Equipment for non-3GPP access via free5gc N3IWF V3.1.1

### Recommended Environment
UE-non3GPP has been tested against the following environment:
* SO: Ubuntu 20.04 (LTS) x64
* Uname -r: 5.4.0-122-generic
* Memory: 1 GB
* Disk: 25 GB

#### Prerequisites
UE-non3GPP was built and tested with Go 1.14.4. You can check the Go version on your system with the following command:
```
go version
```
If another version of Go is installed, remove the existing version and install Go 1.14.4 with the following sequence of commands (assuming your current version of Go is in the default location):
```
sudo rm -rf /usr/local/go
wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
sudo tar -C /usr/local -zxvf go1.14.4.linux-amd64.tar.gz
```
However, if Go is not installed on your system you should run the following commands:
```
wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
sudo tar -C /usr/local -zxvf go1.14.4.linux-amd64.tar.gz
mkdir -p ~/go/{bin,pkg,src}
# The following commands assume that your shell is bash
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin:$GOROOT/bin' >> ~/.bashrc
echo 'export GO111MODULE=auto' >> ~/.bashrc
source ~/.bashrc
```
You can get more detailed information about installing ```golang``` from the [official website of golang](https://go.dev/doc/install)


### Config UE-non3GPP
Clone the project with the following command:
```
git clone -b develop https://github.com/LABORA-INF-UFG/UE-non3GPP.git 
```

Open the ```conf/config.yaml``` file in your preferred text editor and change the configuration parameters as described in the following table:
| Field Name  |  Description |
| ------------- | ------------- |
| `authsubscription.permanentkeyvalue`  | This parameter must be set to the same value as the `permanentKeyValue` field of the `subscriptionData.authenticationData.authenticationSubscription` collection existing in the Free5GC MongoDB, which records the registration data of the UEs. In free5gc GUI (new subscriber) the attribute is represented by the `K*` field of the registration form.  |
| `authsubscription.opcvalue`  | This parameter must be set to the same value as the `opcValue` field of the `subscriptionData.authenticationData.authenticationSubscription` collection existing in the Free5GC MongoDB, which records the registration data of the UEs.  |
| `authsubscription.opvalue`  | This parameter must be set to the same value as the `opValue` field of the `subscriptionData.authenticationData.authenticationSubscription` collection existing in the Free5GC MongoDB, which records the registration data of the UEs. In free5gc GUI (new subscriber) the attribute is represented by the `Operator Code Value*` field of the registration form.  |
| `authsubscription.sequencenumber`  | This parameter must be set to the same value as the `sequencenumber` field of the `subscriptionData.authenticationData.authenticationSubscription` collection existing in the Free5GC MongoDB, which records the registration data of the UEs. In free5gc GUI (new subscriber) the attribute is represented by the `SQN*` field of the registration form. This field contains a hexadecimal value that is incremented in MongoDB by the N3IWF each time the same UE registers in the 5GC, therefore, for the correct functioning of UE-non3GPP, the hexadecimal value of the configuration parameter must be modified in order to be equivalent to the existing one in the mongoDB base. |
| `msin`  | This parameter must be configured with the last N values of the `ueId` field of the `subscriptionData.authenticationData.authenticationSubscription` collection existing in Free5GC MongoDB, which records the registration data of the UEs. In the free5gc (new subscriber) GUI, the attribute is represented by the `SUPI (IMSI)*` field of the registration form. The value of the `SUPI (IMSI)*` field is made up of the `mcc` code (eg: 208), followed by the `mnc` code (eg: 93), followed by a numerical sequence that represents the value to be assigned to the `msin` parameter. For example, assuming that in the free5gc GUI (new subscriber) the `SUPI (IMSI)*` field has the value `208930000000001`, then the value to assign to the parameter msin in UE-non3GPP config file is `0000000001`  |
| `hplmn.mcc`  | This parameter makes up the first 3 digits of `SUPI (IMSI)*` field and represents the Mobile Country Code |
| `hplmn.mnc`  | This parameter makes up digits 4 and 5 of `SUPI (IMSI)*` and represents the Mobile Network Code.  |
| `ranuengapid`  | TODO  |
| `amfuengapid`  | TODO  |
| `authenticationmanagementfield`  | TODO  |
| `localpublicipaddr`  | TODO  |
| `localpublicportudpconnection`  | TODO  |
| `linkgre.name`  | TODO  |
| `ipsecinterfacename`  | TODO  |
| `ipsecinterfacemark`  | TODO  |
| `snssai.sst`  | TODO  |
| `snssai.sd`  | TODO  |
| `snssai.sd`  | TODO  |
| `pdusessionid`  | TODO  |
| `dnnstring`  | TODO  |
| `n3iwfinfo.ikebindaddress`  | TODO  |
| `n3iwfinfo.ikebindport`  | TODO  |
| `n3iwfinfo.ipsecifaceprotocol`  | TODO  |


### Start Free5GC and N3IWF
TODO

### Register UE-non3GPP into Free5GC
TODO

### Config UE-non3GPP
TODO

### Start UE-non3GPP
TODO
