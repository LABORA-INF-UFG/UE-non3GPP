# Web Cnoonsole for UE-non3GPP
Set of APIs and Web DashBoard to monitor the connection between User Equipment for non-3GPP and free5gc N3IWF

## Start API Server
Server settings are contained in the ```UE-non3GPP/webconsole/config.config.yaml``` file. In this file you can customize the IP address and port where the services will be available. To start the server, run the following command, inside the webconsole folder.
```
go run  server.go
```
Attention, for correct operation it is mandatory to have UE-non3GPP running. After the above command the following services will be available:

### Connection Info between UE-non3GPP and N3IWF
Provides information about connection metrics during registration procedures between UE and N3IWF (RegisterTime, PduTime, SecurityTime, AuthTime and IpsecTime)
```
<<ue-non3gpp-server-ip>>:<<ue-non3gpp-server-port>>/ue/info
```

### Network Interface Throughput Monitor
Collects network interface throughput information over a time interval. It has two mandatory path parameters: (i) **:interface** which must be replaced with the name of the network interface to be monitored (__gretun1__ for data plane or __ipsec0-default__ for control plane); : (ii) **:interval** which must be replaced by an integer value that represents the number of seconds in which you want to perform the collection, for example, when passing the integer 10, the values will be collected every 1 second for 10 seconds. For every second will be calculated: ThroughputIn and ThroughputOut
```
<<ue-non3gpp-server-ip>>:<<ue-non3gpp-server-port>>/ue/interface/:interface/throughput/monitor/:interval
```

### Network Interface Status Monitor
Provides information about momentary traffic on a network interface over a period of time. . It has two mandatory path parameters: (i) **:interface** which must be replaced with the name of the network interface to be monitored (__gretun1__ for data plane or __ipsec0-default__ for control plane); : (ii) **:interval** which must be replaced by an integer value that represents the number of seconds in which you want to perform the collection, for example, when passing the integer 10, the values will be collected every 1 second for 10 seconds. For every second will be calculated: BytesRecv, BytesSent, PacketsRecv and PacketsSent
```
<<ue-non3gpp-server-ip>>:<<ue-non3gpp-server-port>>/ue/interface/:interface/network/status/:interval
```

### FrontEnd
Angular project
Dependencias:
node V18 --> Passos aqui - https://joshtronic.com/2022/04/24/how-to-install-nodejs-18-on-ubuntu-2004-lts/
sudo apt update
sudo apt upgrade
sudo apt install -y curl
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

Instalar versão atualizada do npm ``` npm install -g npm@10.2.0 ```
Instalar Angular CLI ``` npm install -g @angular/cli ```
Entrar em WebConsole e rodar ```npm install``` para instalar as dependencias do Angular.

No terminal do linux abrir o arquivo: ```sudo nano /etc/sysctl.conf```
Adicionar a seguinte linha no arquivo: ``` fs.inotify.max_user_watches=524288 ```
Atualizar e salvar: ```sudo sysctl -p```
Inicializar o serviço ANgular: ```ng serve --host <<ue-non3gpp-ip>>```


