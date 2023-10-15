# WebC onsole for UE-non3GPP
Set of APIs and Web DashBoard to monitor the connection between User Equipment for non-3GPP and free5gc N3IWF

### Start API Server
Server settings are contained in the ```UE-non3GPP/webconsole/config.config.yaml``` file. In this file you can customize the IP address and port where the services will be available. To start the server, run the following command, inside the webconsole folder.
```
go run  server.go
```
Attention, for correct operation it is mandatory to have UE-non3GPP running. After the above command the following services will be available:
