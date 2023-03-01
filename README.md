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
| `localpublicipaddr`  | This parameter represents the IP address of the machine where UE-non3GPP is running. It will be used by N3IWF to maintain active communication  |
| `localpublicportudpconnection`  | This parameter represents the port that N3IWF will use to forward messages to UE-non3GPP  |
| `linkgre.name`  | This parameter will be used to create the network interface through which it will be possible to establish communication with the data network through the 5GC  |
| `ipsecinterfacename`  | This parameter will be used to create the network interface through which all control communication between N3IWF and UE-non3GPP will take place.  |
| `ipsecinterfacemark`  | This parameter represents an IPSec virtual interface tag (any value except 0, default value is 7 if not defined). It must be the same value assigned to the configuration file of the N3IWF to which UE-non3GPP will connect  |
| `snssai.sst`  | Single Network Slice Selection Assistance Information - Slice/Service Type (1 byte hex string, range: 0~F)  |
| `snssai.sd`  | Single Network Slice Selection Assistance Information - Slice Differentiator (3 bytes hex string, range: 000000~FFFFFF)  |
| `pdusessionid`  | TODO  |
| `dnnstring`  | TODO  |
| `n3iwfinfo.ikebindaddress`  | This parameter must be configured with the IP address of the N3IWF  |
| `n3iwfinfo.ikebindport`  | This parameter must be configured with the N3IWF IKE interface access port. Must contain the same value assigned to the N3IWF configuration file  |
| `n3iwfinfo.ipsecifaceprotocol`  | Protocol used in the communication process. UDP default value  |


### Run UE-non3GPP
After adjusting all the configuration parameters, registering the UE in free5GC with the same parameters used in the configuration file and making sure that 5GC and N3IWF are running, execute the following command:

```
go run cmd/main.go ue
```
After execution, open another terminal on the same machine and check if a new network interface (eg gretun1) has been created.

### Testing how UE-non3GPP works
To test the operation of UE-non3GPP run the command below:
```
ping -I gretun1 8.8.8.8
```
The above command triggers a connection (ping) to google. If everything is in perfect working order, the terminator must present a positive response to the request. This means that you can direct network traffic to the `gretun1` interface and data network access via 5GC will perform satisfactorily.