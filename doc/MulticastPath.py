from collections import defaultdict
from sets import Set
from heapq import  heappop, heappush

# POX dependencies
from pox.openflow.discovery import Discovery
from pox.core import core
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import *
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import sys
log = core.getLogger()


class MulticastPath(object)
"""Manages multicast route calculation and installation for a single pair of multicast group and multicast sender."""
    def __init__(self, src_ip, src_router_dpid, dst_mcast_address):
        self.src_ip = src_ip                     #IP switcha zrodlowego
        self.src_router_dpid = src_router_dpid   #datapath id switcha zrodlowego
        self.dst_mcast_address = dst_mcast_address
        self.path_tree_map = defaultdict(lambda : None)     # self.path_tree_map[router_dpid] = Complete path from receiver router_dpid to src   pelne sciezki zlozone z datapath id routerow ktore są na drodze od odbiorcow do zrodla (dla kazdego odbiorcy osobna sciezka)
        self.edges = []
        self.node_list = ["00.00","01.01","02.02"]                 # List of all managed router dpids, trzeba dodac na sztywno
        self.installed_node_list = []       # List of all router dpids with rules currently installed
        self.receivers = []                 # Tuples of (router_dpid, port)
        self.calc_path_tree_dijkstras(groupflow_trace_event)
        self.adjacency = defaultdict(lambda : defaultdict(lambda : None))   #slownik definiujacy jaki jest port wyjsciowy z ktorego         jest wysylany pakiet z jednego switcha w parze do drugiego
        
        
    def get_reception_state(self, mcast_group, src_ip):
        """Returns locations to which traffic must be routed for the specified multicast address and sender IP.
        Returns a list of tuples of the form (router_dpid, output_port - port na ktorym przychodza pakiety ze zrodla do docelowego).
        """
        # log.debug('Calculating reception state for mcast group: ' + str(mcast_group) + ' Source: ' + str(src_ip))
        reception_state = []
        if mcast_group==  "10"   and src_ip== "9":    #na sztywno podac
           reception_state.append(("01.01, "1"))
           reception_state.append(("02.02", "2"))
           
        
        return reception_state

        
    def calc_path_tree_dijkstras(self):
        """Calculates a shortest path tree from the group sender to all network switches, and caches the resulting tree.
        Note that this function does not install any flow modifications."""
        
        
        nodes = set(self.node_list)
        #wagi laczy pomiedzy parami switchy [src dpid,dest dpid,koszt] - trzeba dodac na sztywno dla wszystkich laczy
        edges.append(["00.00", "01.01", 1])
        edges.append(["00.00", "02.02", 3])
        edges.append(["01.01", "02.02", 1])
        #na sztywno trzeba tez dodac port (output port) miedzy wszystkimi parami switchy
        self.adjacency["00.00"]["01.01"] =  "1" ########
        self.adjacency["00.00"]["02.02"] =  "2" ########
        self.adjacency["01.01"]["02.02"] =  "2" ########
        graph = defaultdict(list)
        for src,dst,cost in edges:
            graph[src].append((cost, dst))
     
        path_tree_map = defaultdict(lambda : None)
        queue, seen = [(0,self.src_router_dpid,())], set()    #najpierw nodem1 jest switch zrodlowy, na koncu to bedzie wygladalo tak:[receiver,(1,2,3,...,zrodlowy)]
        while queue:
            (cost,node1,path) = heappop(queue)
            if node1 not in seen:
                seen.add(node1)
                path = (node1, path)
                path_tree_map[node1] = path
     
                for next_cost, node2 in graph.get(node1, ()):
                    if node2 not in seen:
                        new_path_cost = cost + next_cost
                        heappush(queue, (new_path_cost, node2, path))
        
        self.path_tree_map = path_tree_map
        #dla kazdego wezla zdefiniowana zostaje sciezka switchy chyba w kierunku od niego do zrodlowego
        log.debug('Calculated shortest path tree for source at router_dpid: ' + dpid_to_str(self.src_router_dpid))
        for node in self.path_tree_map:
            log.debug('Path to Node ' + dpid_to_str(node) + ': ' + str(self.path_tree_map[node]))
        
    def install_openflow_rules(self):
      
        self.calc_path_tree_dijkstras()
        
        """Selects routes for active receivers from the cached shortest path tree, and installs/removes OpenFlow rules accordingly."""
        reception_state = self.get_reception_state(self.dst_mcast_address, self.src_ip)
        log.debug('Receivers for this multicast group are: ' + str(self.dst_mcast_address) + ': ' + str(reception_state))
        outgoing_rules = defaultdict(lambda : None)
        
            
        # Calculate the paths for the specific receivers that are currently active from the previously
        # calculated mst
        edges_to_install = []
        calculated_path_router_dpids = []
        for receiver in reception_state:
            if receiver[0] == self.src_router_dpid:
                continue
            if receiver[0] in calculated_path_router_dpids:
                continue
            
            # log.debug('Building path for receiver on router: ' + dpid_to_str(receiver[0]))
            receiver_path = self.path_tree_map[receiver[0]]
            log.debug('Receiver path for receiver ' + str(receiver[0]) + ': ' + str(receiver_path))
            if receiver_path is None:
                log.warn('Path could not be determined for receiver ' + dpid_to_str(receiver[0]) + ' (network is not fully connected)')
                continue
                
            while receiver_path[1]:
                edges_to_install.append((receiver_path[1][0], receiver_path[0])) #dla kazdej pary switchy na sciezce: dodaj ja do tych dla ktorych trzeba zainstalowac regule
                receiver_path = receiver_path[1]
            calculated_path_router_dpids.append(receiver[0])
                    
        # Get rid of duplicates in the edge list 
        edges_to_install = list(Set(edges_to_install))
        if not edges_to_install is None:
            # log.info('Installing edges:')
            for edge in edges_to_install:
                log.debug('Installing: ' + str(edge[0]) + ' -> ' + str(edge[1]))
    
        
        for edge in edges_to_install:
            if edge[0] in outgoing_rules:
                # Add the output action to an existing rule if it has already been generated
                output_port = self.adjacency[edge[0]][edge[1]]
                outgoing_rules[edge[0]].actions.append(of.ofp_action_output(port = output_port))  #regula jest dodawana tylko dla tych switchy z ktorych ruch jest wysylany, nie na odwrot
                #log.debug('ER: Configured router ' + dpid_to_str(edge[0]) + ' to forward group ' + \
                #    str(self.dst_mcast_address) + ' to next router ' + \
                #    dpid_to_str(edge[1]) + ' over port: ' + str(output_port))
            else:
                # Otherwise, generate a new flow mod
                msg = of.ofp_flow_mod()
                msg.hard_timeout = 0
                msg.idle_timeout = 0
                if edge[0] in self.installed_node_list:
                    msg.command = of.OFPFC_MODIFY
                else:
                    msg.command = of.OFPFC_ADD
                msg.match.dl_type = 0x800   # IPV4
                msg.match.nw_dst = self.dst_mcast_address
                msg.match.nw_src = self.src_ip
                output_port = self.adjacency[edge[0]][edge[1]]
                msg.actions.append(of.ofp_action_output(port = output_port))
                outgoing_rules[edge[0]] = msg
                #log.debug('NR: Configured router ' + dpid_to_str(edge[0]) + ' to forward group ' + \
                #    str(self.dst_mcast_address) + ' to next router ' + \
                #    dpid_to_str(edge[1]) + ' over port: ' + str(output_port))
        
"""        for receiver in reception_state:
            if receiver[0] in outgoing_rules:
                # Add the output action to an existing rule if it has already been generated
                output_port = receiver[1]
                outgoing_rules[receiver[0]].actions.append(of.ofp_action_output(port = output_port))
                #log.debug('ER: Configured router ' + dpid_to_str(receiver[0]) + ' to forward group ' + \
                #        str(self.dst_mcast_address) + ' to network over port: ' + str(output_port))
            else:
                # Otherwise, generate a new flow mod
                msg = of.ofp_flow_mod()
                msg.hard_timeout = 0
                msg.idle_timeout = 0
                if receiver[0] in self.installed_node_list:
                    msg.command = of.OFPFC_MODIFY
                else:
                    msg.command = of.OFPFC_ADD
                msg.match.dl_type = 0x800   # IPV4
                msg.match.nw_dst = self.dst_mcast_address
                msg.match.nw_src = self.src_ip
                output_port = receiver[1]
                msg.actions.append(of.ofp_action_output(port = output_port))
                outgoing_rules[receiver[0]] = msg
                #log.debug('NR: Configured router ' + dpid_to_str(receiver[0]) + ' to forward group ' + \
                #        str(self.dst_mcast_address) + ' to network over port: ' + str(output_port))    """
        
        # Setup empty rules for any router not involved in this path
        for router_dpid in self.node_list:
            if not router_dpid in outgoing_rules and router_dpid in self.installed_node_list:
                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x800   # IPV4
                msg.match.nw_dst = self.dst_mcast_address
                msg.match.nw_src = self.src_ip
                msg.command = of.OFPFC_DELETE
                outgoing_rules[router_dpid] = msg
                #log.debug('Removed rule on router ' + dpid_to_str(router_dpid) + ' for group ' + str(self.dst_mcast_address))
        
        for router_dpid in outgoing_rules:
            connection = core.openflow.getConnection(router_dpid)
            if connection is not None:
                connection.send(outgoing_rules[router_dpid])
                if not outgoing_rules[router_dpid].command == of.OFPFC_DELETE:
                    self.installed_node_list.append(router_dpid)
                else:
                    self.installed_node_list.remove(router_dpid)
            else:
                log.warn('Could not get connection for router: ' + dpid_to_str(router_dpid))
        
        log.debug('New flows installed for Group: ' + str(self.dst_mcast_address) + ' Source: ' + str(self.src_ip))
        
        
    def _go_up (event):
    # Event handler called when POX goes into up state
    # (we actually listen to the event in launch() below)
    log.info("Skeleton application ready.")
    #self.install_openflow_rules()
    self.calc_path_tree_dijkstras()
    print "Let's talk about."

  
@poxutil.eval_args
def launch (src_ip="9", src_router_dpid="00.00", dst_mcast_address="10",__INSTANCE__=None):
    install_rules = MulticastPath(src_ip, src_router_dpid, dst_mcast_address)
    core.register('MulticastPath', install_rules)
    core.addListenerByName("UpEvent", _go_up)