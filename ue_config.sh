#!/usr/bin/env bash

N3IWF_IKE_BIND_ADDRESS="146.190.52.205"
N3IWF_UE_ADDR="10.0.0.1/24"
sudo ip link add name ipsec0 type vti local ${N3IWF_IKE_BIND_ADDRESS} remote 0.0.0.0 key 5
sudo ip addr add ${N3IWF_UE_ADDR} dev ipsec0
sudo ip link set ipsec0 up
sleep 1