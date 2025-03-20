# 4480_SDN
CS 4480 Spring 2025- Programming Assignment 2. Simple OpenFlow application using the POX SDN framework

## install mn
```
sudo apt-get update
sudo apt-get install mininet
```

## install pox
```
git clone http://github.com/noxrepo/pox
```

## Run commands
```
sudo mn --topo single,6 --mac --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow10
```
```
python pox.py openflow.of_01 --port=6633 more_app
```
