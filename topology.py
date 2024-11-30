#!/usr/bin/python

"""
Modified linuxrouter.py: Network with Linux IP routers

This topology introduces a router in front of each switch,
connected to a main router. Each subnet is defined as before.
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

# class LinuxRouter( Node ):
#     "A Node with IP forwarding enabled."

#     def config( self, **params ):
#         super( LinuxRouter, self).config( **params )
#         # Enable forwarding on the router
#         self.cmd( 'sysctl net.ipv4.ip_forward=1' )

#     def terminate( self ):
#         self.cmd( 'sysctl net.ipv4.ip_forward=0' )
#         super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):
    def build( self, **_opts ):
        mainRouter = self.addHost( 'r0' )

        routerIPs = ['10.0.0.1/24', '11.0.0.1/24', '12.0.0.1/24']
        intermediateRouters = []
        switches = []
        for i in range(3):
            ri = self.addHost( f'ri{i}' )
            s = self.addSwitch( f's{i}' )
            intermediateRouters.append(ri)
            switches.append(s)

            self.addLink(
                mainRouter, ri,
                intfName1=f'r0-eth{i}',
                intfName2=f'ri{i}-eth0',
            )

            self.addLink(
                s, ri,
                intfName1=f's{i}-eth0',
                intfName2=f'ri{i}-eth1',
            )

        for i in range(3):
            for j in range(5):
                hostName = f'h{1+i}{j}'
                h = self.addHost(hostName, ip=f'{10+i}.0.0.{100+j}/24', defaultRoute=f'via {10 + i}.0.0.1' )
                self.addLink(
                    h, switches[i],
                    intfName1=f'{hostName}-eth0',
                    intfName2=f's{i}-eth{1+j}'
                )

def run():
    "Test linux router with intermediary routers"
    topo = NetworkTopo()
    net = Mininet( topo=topo ) 
    net.start()
    hostsNets = ['10.0.0.1/24', '11.0.0.1/24', '12.0.0.1/24']
    for i in range(3):
        net.get('r0').cmd(f'ifconfig r0-eth{i} 192.168.0.{1 + (i * 64)}/26')
        net.get(f'ri{i}').cmd(f'ifconfig ri{i}-eth0 192.168.0.{2 + (i * 64)}/26')
        net.get(f'ri{i}').cmd(f'ifconfig ri{i}-eth1 {hostsNets[i]}')

    for i in range(3):
        net.get(f'ri{i}').cmd(
            f'xterm -T "Router ri{i}" -n "Router ri{i}" -e build/RouterEx {i + 1} &'
        )
    net.get('r0').cmd(
        f'xterm -T "Main Router r0" -n "Main Router r0" -e build/RouterEx 0 &'
    )

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
