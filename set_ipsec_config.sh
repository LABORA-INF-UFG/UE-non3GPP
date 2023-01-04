#!/usr/bin/env bash

N3IWF_IKE_BIND_ADDRESS="137.184.44.146"
N3IWF_UE_ADDR="10.0.0.1/24"
IP_UE="146.190.54.29"

sudo ip link add name ipsec0 type vti local ${N3IWF_IKE_BIND_ADDRESS} remote 0.0.0.0 key 5
sudo ip addr add ${N3IWF_UE_ADDR} dev ipsec0
sudo ip link set ipsec0 up
sleep 1

//teste
sudo ip link add veth3 type veth
ip addr add 146.190.54.29/24 dev veth3
ip link set lo up
ip link set veth3 up
ip link add ipsec0 type vti local 146.190.54.29 remote 137.184.44.146 key 5
ip link set ipsec0 up