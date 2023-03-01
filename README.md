# UE-non3GPP
User Equipment for non-3GPP access via N3IWF

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


### UE-non3GPP install
Clone the project with the following command:
```
git clone -b develop https://github.com/LABORA-INF-UFG/UE-non3GPP.git 
```


### Start Free5GC and N3IWF
TODO

### Register UE-non3GPP into Free5GC
TODO

### Config UE-non3GPP
TODO

### Start UE-non3GPP
TODO
