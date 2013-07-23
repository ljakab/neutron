# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Hareesh Puthalath, Cisco Systems, Inc.

import eventlet
from eventlet import semaphore
import netaddr
from oslo.config import cfg

from quantum.agent.common import config
from quantum.agent.linux import external_process
from quantum.agent.linux import interface
from quantum.agent.linux import ip_lib
from quantum.agent import rpc as agent_rpc
from quantum.common import constants as l3_constants
from quantum.common import topics
from quantum.common import utils as common_utils
from quantum import context
from quantum import manager
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import loopingcall
from quantum.openstack.common import periodic_task
from quantum.openstack.common.rpc import common as rpc_common
from quantum.openstack.common.rpc import proxy
from quantum.openstack.common import service
from quantum.plugins.cisco.l3.common import constants as cl3_constants
from quantum.plugins.cisco.l3.agent.csr1000v import cisco_csr_network_driver
from quantum import service as quantum_service

import pdb

LOG = logging.getLogger(__name__)

N_ROUTER_PREFIX = 'nrouter-'

class L3PluginApi(proxy.RpcProxy):
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(L3PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_routers(self, context, fullsync=True, router_id=None):
        """Make a remote process call to retrieve the sync data for routers."""
        router_ids = [router_id] if router_id else None
        #Note that the l3_cfg_agent makes a call on 'cfg_sync_routers'
        return self.call(context,
                         self.make_msg('cfg_sync_routers', host=self.host,
                                       fullsync=fullsync,
                                       router_ids=router_ids),
                         topic=self.topic)

    def get_external_network_id(self, context):
        """Make a remote process call to retrieve the external network id.

        @raise common.RemoteError: with TooManyExternalNetworks
                                   as exc_type if there are
                                   more than one external network
        """
        return self.call(context,
                         self.make_msg('get_external_network_id',
                                       host=self.host),
                         topic=self.topic)


#Additional class to store the Hosting Entities to driver bindings.
#Thus we can reuse drivers to different logical routers in the same
# hosting entity
class HostingEntities(object):

    def __init__(self):
        self.router_id_hosting_entities = {}
        self._drivers = {}

    def get_driver(self, router_id):
        hosting_entity = self.router_id_hosting_entities.get(router_id, None)
        if hosting_entity is not None:
            driver = self._drivers.get(hosting_entity['id'], None)
            if driver is None:
                LOG.error(_("No valid driver found for Hosting Entity: %s"),
                          hosting_entity)['id']
        else:
            LOG.error(_("Cannot find hosting entity for: %s"), hosting_entity['id'])
        return driver

    def set_driver(self, router_id, router):
        hosting_entity = router['hosting_entity']
        _he_id = hosting_entity['id']
        _he_type = hosting_entity['host_type']
        _he_ip = hosting_entity['ip_address']
        _he_port = hosting_entity['port']
        _he_created_at = hosting_entity['created_at']
        _he_user = 'lab'
        _he_passwd = 'lab'

        _csr_driver = cisco_csr_network_driver.CiscoCSRDriver(_he_ip,
                                                               _he_port,
                                                               _he_user,
                                                               _he_passwd)
        self.router_id_hosting_entities[router_id] = hosting_entity
        self._drivers[_he_id] = _csr_driver

    def remove_driver(self, router_id):
        del self.router_id_hosting_entities[router_id]
        for he_id in self._drivers.keys():
            if he_id not in self.router_id_hosting_entities.values():
                del self._drivers[he_id]


class RouterInfo(object):

    def __init__(self, router_id, root_helper, use_namespaces, router):
        self.router_id = router_id
        self.ex_gw_port = None
        self.internal_ports = []
        self.floating_ips = []
        self.root_helper = root_helper
        self.use_namespaces = use_namespaces
        self.router = router
        self.routes = []

    def router_name(self):
        return N_ROUTER_PREFIX+self.router_id


class L3NATAgent(manager.Manager):

    OPTS = [
        cfg.StrOpt('external_network_bridge', default='br-ex',
                   help=_("Name of bridge used for external network "
                          "traffic.")),
        cfg.StrOpt('interface_driver',
                   help=_("The driver used to manage the virtual "
                          "interface.")),
        cfg.IntOpt('metadata_port',
                   default=9697,
                   help=_("TCP Port used by Quantum metadata namespace "
                          "proxy.")),
        cfg.IntOpt('send_arp_for_ha',
                   default=3,
                   help=_("Send this many gratuitous ARPs for HA setup, "
                          "set it below or equal to 0 to disable this "
                          "feature.")),
        # Hareesh : Temporarily setting this to False if needed
        cfg.BoolOpt('use_namespaces', default=True,
                    help=_("Allow overlapping IP.")),
        cfg.StrOpt('router_id', default='',
                   help=_("If namespaces is disabled, the l3 agent can only"
                          " confgure a router that has the matching router "
                          "ID.")),
        cfg.BoolOpt('handle_internal_only_routers',
                    default=True,
                    help=_("Agent should implement routers with no gateway")),
        cfg.StrOpt('gateway_external_network_id', default='',
                   help=_("UUID of external network for routers implemented "
                          "by the agents.")),
        cfg.BoolOpt('enable_metadata_proxy', default=True,
                    help=_("Allow running metadata proxy.")),
        cfg.BoolOpt('use_hosting_entities', default=True,
                    help=_("Allow hosting entities for routing service.")),

    ]

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)
        self.router_info = {}

        if not self.conf.interface_driver:
            raise SystemExit(_('An interface driver must be specified'))
        try:
            self.driver = importutils.import_object(self.conf.interface_driver,
                                                    self.conf)
        except Exception:
            msg = _("Error importing interface driver "
                    "'%s'") % self.conf.interface_driver
            raise SystemExit(msg)

        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.PLUGIN, host)
        self.fullsync = True
        self.sync_sem = semaphore.Semaphore(1)
        #Hareesh
        if self.conf.use_hosting_entities:
            self._he = HostingEntities()
        super(L3NATAgent, self).__init__(host=self.conf.host)

    def _csr_get_vrf_name(self, ri):
        return ri.router_name()[:self.driver.DEV_NAME_LEN]

    def _csr_create_vrf(self, ri):
        vrf_name = self._csr_get_vrf_name(ri)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.create_vrf(vrf_name)

    def _csr_remove_vrf(self, ri):
        vrf_name = self._csr_get_vrf_name(ri)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.remove_vrf(vrf_name)

    def _csr_create_subinterface(self, ri, intfc_no,
                                 vlanid, ip_cidrs ):
        if len(ip_cidrs) > 1:
            #ToDo (Hareesh): Implement ip_cidrs>1
            raise Exception("Not implemented yet")
            #LOG.Error("Multiple entries in ip_cidrs %s" % ip_cidrs)
        vrf_name = self._csr_get_vrf_name(ri)
        ip_cidr = ip_cidrs[0]
        netmask = netaddr.IPNetwork(ip_cidr).netmask
        gateway_ip = ip_cidr.split('/')[0]
        interface = 'GigabitEthernet'+str(intfc_no)+'.'+str(vlanid)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.create_subinterface(interface,
                                       vlanid,
                                       vrf_name,
                                       gateway_ip,
                                       netmask)

    def _csr_remove_subinterface(self, ri, intc_no, vlan_id, ip):
        vrf_name = self._csr_get_vrf_name(ri)
        interface = 'GigabitEthernet'+str(intc_no)+'.'+str(vlan_id)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.remove_subinterface(interface, vlan_id, vrf_name, ip)

    def _csr_add_internalnw_nat_rules(self, ri, int_intfc_no,
                                           ext_intfc_no,
                                           gw_ip, internal_cidr,
                                           inner_vlanid, outer_vlanid):
        vrf_name = self._csr_get_vrf_name(ri)
        acl_no = 'acl_'+str(inner_vlanid)
        internal_net = netaddr.IPNetwork(internal_cidr).network
        netmask = netaddr.IPNetwork(internal_cidr).hostmask
        inner_intfc = 'GigabitEthernet'+str(int_intfc_no)+'.'+str(inner_vlanid)
        outer_intfc = 'GigabitEthernet'+str(ext_intfc_no)+'.'+str(outer_vlanid)

        #nat_pool_name = 'snat_net_'+(ri.ns_name()[:self.driver.DEV_NAME_LEN])
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.nat_rules_for_internet_access(acl_no,
                                                       internal_net,
                                                       netmask,
                                                       inner_intfc,
                                                       outer_intfc,
                                                       vrf_name)

    def _csr_remove_internalnw_nat_rules(self, ri, int_intfc_no,
                                         ext_intfc_no,
                                         internal_cidr,
                                         inner_vlanid,
                                         outer_vlanid):
        vrf_name = self._csr_get_vrf_name(ri)
        acl_no = 'acl_'+str(inner_vlanid)
        internal_net = netaddr.IPNetwork(internal_cidr).network
        netmask = netaddr.IPNetwork(internal_cidr).hostmask
        inner_intfc = 'GigabitEthernet'+str(int_intfc_no)+'.'+str(inner_vlanid)
        outer_intfc = 'GigabitEthernet'+str(ext_intfc_no)+'.'+str(outer_vlanid)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.remove_nat_rules_for_internet_access(acl_no,
                                                           internal_net,
                                                           netmask,
                                                           inner_intfc,
                                                           outer_intfc,
                                                           vrf_name)

    def _csr_add_floating_ip(self,ri, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.add_floating_ip(floating_ip, fixed_ip, vrf_name)

    def _csr_remove_floating_ip(self, ri, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.remove_floating_ip(floating_ip, fixed_ip, vrf_name)

    def _csr_add_default_route(self, ri, gw_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.add_default_static_route(gw_ip, vrf_name)

    def _csr_remove_default_route(self, ri, gw_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        csr_driver = self._he.get_driver(ri.router_id)
        csr_driver.remove_default_static_route(gw_ip, vrf_name)

    def _csr_update_routing_table(self, ri, cmd, route):
        #cmd = ['ip', 'route', operation, 'to', route['destination'],
        #       'via', route['nexthop']]
        #self._update_routing_table(ri, 'replace', route)
        #self._update_routing_table(ri, 'delete', route)
        vrf_name = self._csr_get_vrf_name(ri)
        destination_net = netaddr.IPNetwork(route['destination'])
        dest = destination_net.network
        dest_mask = destination_net.netmask
        next_hop = route['nexthop']
        csr_driver = self._he.get_driver(ri.router_id)
        if cmd is 'replace':
            csr_driver.add_static_route(dest, dest_mask,
                                        next_hop, vrf_name)
        elif cmd is 'delete':
            csr_driver.remove_static_route(dest, dest_mask,
                                           next_hop, vrf_name)
        else:
            LOG.error(_('Unknown route command %s'), cmd)
        pass

    def _fetch_external_net_id(self):
        """Find UUID of single external network for this agent."""
        if self.conf.gateway_external_network_id:
            return self.conf.gateway_external_network_id
        try:
            return self.plugin_rpc.get_external_network_id(self.context)
        except rpc_common.RemoteError as e:
            if e.exc_type == 'TooManyExternalNetworks':
                msg = _(
                    "The 'gateway_external_network_id' option must be "
                    "configured for this agent as Quantum has more than "
                    "one external network.")
                raise Exception(msg)
            else:
                raise

    def _router_added(self, router_id, router):
        ri = RouterInfo(router_id, self.root_helper,
                        self.conf.use_namespaces, router)
        self.router_info[router_id] = ri
        #Hareeesh: CSR, Note that we are not adding the metadata NAT rules now
        if self.conf.use_hosting_entities:
            self._he.set_driver(router_id, router)
            self._csr_create_vrf(ri)

    def _router_removed(self, router_id):
        ri = self.router_info[router_id]
        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        self.process_router(ri)
        del self.router_info[router_id]
        #Hareesh : CSR
        if self.conf.use_hosting_entities:
            self._csr_remove_vrf(ri)
            self._he.remove_driver(router_id)

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def process_router(self, ri):

        ex_gw_port = self._get_ex_gw_port(ri)
        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        existing_port_ids = set([p['id'] for p in ri.internal_ports])
        current_port_ids = set([p['id'] for p in internal_ports
                                if p['admin_state_up']])
        new_ports = [p for p in internal_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.internal_ports if
                     p['id'] not in current_port_ids]

        for p in new_ports:
            self._set_subnet_info(p)
            ri.internal_ports.append(p)
            self.internal_network_added(ri, ex_gw_port,
                                        p['ip_cidr'],
                                        p['trunk_info'])

        for p in old_ports:
            ri.internal_ports.remove(p)
            self.internal_network_removed(ri, ex_gw_port,
                                          p['ip_cidr'],
                                          p['trunk_info'])

        internal_cidrs = [p['ip_cidr'] for p in ri.internal_ports]

        if ex_gw_port and not ri.ex_gw_port:
            self._set_subnet_info(ex_gw_port)
            self.external_gateway_added(ri, ex_gw_port, internal_cidrs)
        elif not ex_gw_port and ri.ex_gw_port:
            self.external_gateway_removed(ri, ri.ex_gw_port,
                                          internal_cidrs)

        if ri.ex_gw_port or ex_gw_port:
            self.process_router_floating_ips(ri, ex_gw_port)

        ri.ex_gw_port = ex_gw_port

        self.routes_updated(ri)

    def process_router_floating_ips(self, ri, ex_gw_port):
        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        existing_floating_ip_ids = set([fip['id'] for fip in ri.floating_ips])
        cur_floating_ip_ids = set([fip['id'] for fip in floating_ips])

        id_to_fip_map = {}

        for fip in floating_ips:
            if fip['port_id']:
                if fip['id'] not in existing_floating_ip_ids:
                    ri.floating_ips.append(fip)
                    self.floating_ip_added(ri, ex_gw_port,
                                           fip['floating_ip_address'],
                                           fip['fixed_ip_address'])

                # store to see if floatingip was remapped
                id_to_fip_map[fip['id']] = fip

        floating_ip_ids_to_remove = (existing_floating_ip_ids -
                                     cur_floating_ip_ids)
        for fip in ri.floating_ips:
            if fip['id'] in floating_ip_ids_to_remove:
                ri.floating_ips.remove(fip)
                self.floating_ip_removed(ri, ri.ex_gw_port,
                                         fip['floating_ip_address'],
                                         fip['fixed_ip_address'])
            else:
                # handle remapping of a floating IP
                new_fip = id_to_fip_map[fip['id']]
                new_fixed_ip = new_fip['fixed_ip_address']
                existing_fixed_ip = fip['fixed_ip_address']
                if (new_fixed_ip and existing_fixed_ip and
                        new_fixed_ip != existing_fixed_ip):
                    floating_ip = fip['floating_ip_address']
                    self.floating_ip_removed(ri, ri.ex_gw_port,
                                             floating_ip, existing_fixed_ip)
                    self.floating_ip_added(ri, ri.ex_gw_port,
                                           floating_ip, new_fixed_ip)
                    ri.floating_ips.remove(fip)
                    ri.floating_ips.append(new_fip)

    def _get_ex_gw_port(self, ri):
        return ri.router.get('gw_port')

    def external_gateway_added(self, ri, ex_gw_port, internal_cidrs):
        #ToDo (Hareesh) : Parameterize interface name
        trunk_info = ex_gw_port['trunk_info']
        outer_vlan = trunk_info['segmentation_id']
        _name = trunk_info['hosting_port_name']
        #Name will be of format 'T2:x' where x is (1,2,..)
        ext_itfc_no = str(int(_name.split(':')[1])*2)
        self._csr_create_subinterface(ri, ext_itfc_no, outer_vlan,
                                      [ex_gw_port['ip_cidr']])
        #ToDo(Hareesh) : Check need to send gratuitous ARP
        ex_gw_ip = ex_gw_port['subnet']['gateway_ip']
        if ex_gw_ip:
            #Set default route via this network's gateway ip
            # In linux : cmd = ['route', 'add', 'default', 'gw', gw_ip]
            self._csr_add_default_route(ri, ex_gw_ip)

        #Apply NAT rules for internal networks
        if len(ri.internal_ports) > 0:
            for internal_port in ri.internal_ports:
                trunk_info = internal_port['trunk_info']
                inner_vlan = trunk_info['segmentation_id']
                _name = trunk_info['hosting_port_name']
                #Name will be of format 'T1:x' where x is the index(1,2,..)
                int_itfc_no = str(int(_name.split(':')[1])*2-1)
                internal_cidr = internal_port['ip_cidr']
                self._csr_add_internalnw_nat_rules(ri, int_itfc_no, ext_itfc_no,
                                                   ex_gw_ip, internal_cidr,
                                                   inner_vlan, outer_vlan)

    def external_gateway_removed(self, ri, ex_gw_port, internal_cidrs):
        ip = ex_gw_port['fixed_ips'][0]['ip_address']
        outer_vlan = ex_gw_port['trunk_info']['segmentation_id']
        _ext_name = ex_gw_port['trunk_info']['hosting_port_name']
        #Name will be of format 'T2:x' where x is the index(1,2,..)
        ext_infc_no = str(int(_ext_name.split(':')[1])*2)
        #Remove internal network NAT rules
        if len(ri.internal_ports) > 0:
            for port in ri.internal_ports:
                trunk_info = port['trunk_info']
                inner_vlan = trunk_info['segmentation_id']
                _name = trunk_info['hosting_port_name']
                #Name will be of format 'T1:x' where x is the index(1,2,..)
                int_itfc_no = str(int(_name.split(':')[1])*2-1)
                internal_cidr = port['ip_cidr']
                self._csr_remove_internalnw_nat_rules(ri, int_itfc_no,
                                                      ext_infc_no,
                                                      internal_cidr,
                                                      inner_vlan,
                                                      outer_vlan)
        ex_gw_ip = ex_gw_port['subnet']['gateway_ip']
        if ex_gw_ip:
        #Remove default route via this network's gateway ip
            self._csr_remove_default_route(ri, ex_gw_ip)
        #Finally, remove external network subinterface
        self._csr_remove_subinterface(ri, ext_infc_no, outer_vlan, ip)


    def internal_network_added(self, ri, ex_gw_port,
                               internal_cidr, trunk_info):
        inner_vlan = trunk_info['segmentation_id']
        _name = trunk_info['hosting_port_name']
        #Name will be of format 'T1:x' where x is the index(1,2,..)
        itfc_no = str(int(_name.split(':')[1])*2-1)
        self._csr_create_subinterface(ri, itfc_no, inner_vlan, [internal_cidr])

        if ex_gw_port:
            ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
            # Hareesh: Apply CSR internal_network_nat_rules
            #External Port
            outer_vlan = ex_gw_port['trunk_info']['segmentation_id']
            _ext_name = ex_gw_port['trunk_info']['hosting_port_name']
            #Name will be of format 'T2:x' where x is the index(1,2,..)
            ext_infc_no = str(int(_ext_name.split(':')[1])*2)
            self._csr_add_internalnw_nat_rules(ri, itfc_no, ext_infc_no,
                                               ex_gw_ip, internal_cidr,
                                               inner_vlan, outer_vlan)

    def internal_network_removed(self, ri, ex_gw_port,
                                 internal_cidr, trunk_info):
        #Hareesh : CSR
        inner_vlan = trunk_info['segmentation_id']
        _name = trunk_info['hosting_port_name']
        #Name will be of format 'T1:x' where x is the index(1,2,..)
        itfc_no = str(int(_name.split(':')[1])*2-1)
        if ex_gw_port:
            outer_vlan = ex_gw_port['trunk_info']['segmentation_id']
            _ext_name = ex_gw_port['trunk_info']['hosting_port_name']
            #Name will be of format 'T2:x' where x is the index(1,2,..)
            ext_itfc_no = str(int(_ext_name.split(':')[1])*2)
            self._csr_remove_internalnw_nat_rules(ri, itfc_no, ext_itfc_no,
                                                  internal_cidr, inner_vlan,
                                                  outer_vlan)
        #Delete sub-interface now
        self._csr_remove_subinterface(ri, itfc_no, inner_vlan, internal_cidr)

    def floating_ip_added(self, ri, ex_gw_port, floating_ip, fixed_ip):
        #ToDo(Hareesh) : Check send gratiotious ARP packet
        self._csr_add_floating_ip(ri, floating_ip, fixed_ip)

    def floating_ip_removed(self, ri, ex_gw_port, floating_ip, fixed_ip):
        self._csr_remove_floating_ip(ri, floating_ip, fixed_ip)

    def router_deleted(self, context, routers):
        """Deal with router deletion RPC message."""
        pdb.set_trace()
        if not routers:
            return
        with self.sync_sem:
            for router in routers:
                router_id = router['id']
                if router_id in self.router_info:
                    try:
                        self._router_removed(router_id)
                    except Exception:
                        msg = _("Failed dealing with router "
                                "'%s' deletion RPC message")
                        LOG.debug(msg, router_id)
                        self.fullsync = True

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        if not routers:
            return
        with self.sync_sem:
            try:
                self._process_routers(routers)
            except Exception:
                msg = _("Failed dealing with routers update RPC message. Exception %s")
                LOG.debug(msg, str(Exception))
                self.fullsync = True

    def router_removed_from_agent(self, context, payload):
        self.router_deleted(context, payload['router_id'])

    def router_added_to_agent(self, context, payload):
        self.routers_updated(context, payload)

    def _process_routers(self, routers, all_routers=False):
        if (self.conf.external_network_bridge and
            not ip_lib.device_exists(self.conf.external_network_bridge)):
            LOG.error(_("The external network bridge '%s' does not exist"),
                      self.conf.external_network_bridge)
            return

        target_ex_net_id = self._fetch_external_net_id()
        # if routers are all the routers we have (They are from router sync on
        # starting or when error occurs during running), we seek the
        # routers which should be removed.
        # If routers are from server side notification, we seek them
        # from subset of incoming routers and ones we have now.
        if all_routers:
            prev_router_ids = set(self.router_info)
        else:
            prev_router_ids = set(self.router_info) & set(
                [router['id'] for router in routers])
        cur_router_ids = set()
        for r in routers:
            if not r['admin_state_up']:
                continue

            # If namespaces are disabled, only process the router associated
            # with the configured agent id.
            if (not self.conf.use_namespaces and
                r['id'] != self.conf.router_id):
                continue

            ex_net_id = (r['external_gateway_info'] or {}).get('network_id')
            if not ex_net_id and not self.conf.handle_internal_only_routers:
                continue

            if ex_net_id and ex_net_id != target_ex_net_id:
                continue
            cur_router_ids.add(r['id'])
            if r['id'] not in self.router_info:
                self._router_added(r['id'], r)
            ri = self.router_info[r['id']]
            ri.router = r
            self.process_router(ri)
        # identify and remove routers that no longer exist
        for router_id in prev_router_ids - cur_router_ids:
            self._router_removed(router_id)

    @periodic_task.periodic_task
    def _sync_routers_task(self, context):
        # we need to sync with router deletion RPC message
        with self.sync_sem:
            if self.fullsync:
                try:
                    if not self.conf.use_namespaces:
                        router_id = self.conf.router_id
                    else:
                        router_id = None
                    routers = self.plugin_rpc.get_routers(
                        context, router_id)
                    self._process_routers(routers, all_routers=True)
                    self.fullsync = False
                except Exception:
                    LOG.exception(_("Failed synchronizing routers"))
                    self.fullsync = True

    def after_start(self):
        LOG.info(_("L3 Cfg Agent started"))

    def routes_updated(self, ri):
        new_routes = ri.router['routes']
        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug(_("Added route entry is '%s'"), route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
            #replace success even if there is no existing route
            self._csr_update_routing_table(ri, 'replace', route)

        for route in removes:
            LOG.debug(_("Removed route entry is '%s'"), route)
            self._csr_update_routing_table(ri, 'delete', route)
        ri.routes = new_routes


class L3NATAgentWithStateReport(L3NATAgent):

    def __init__(self, host, conf=None):
        super(L3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'quantum-l3-cfg-agent',
            'host': host,
            'topic': cl3_constants.L3_CFG_AGENT,
            'configurations': {
                'use_namespaces': self.conf.use_namespaces,
                'router_id': self.conf.router_id,
                'handle_internal_only_routers':
                self.conf.handle_internal_only_routers,
                'gateway_external_network_id':
                self.conf.gateway_external_network_id,
                'interface_driver': self.conf.interface_driver},
            'start_flag': True,
            'agent_type': cl3_constants.AGENT_TYPE_L3_CFG}
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = self._get_ex_gw_port(ri)
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(l3_constants.INTERFACE_KEY,
                                                []))
            num_floating_ips += len(ri.router.get(l3_constants.FLOATINGIP_KEY,
                                                  []))
        configurations = self.agent_state['configurations']
        configurations['routers'] = num_routers
        configurations['ex_gw_ports'] = num_ex_gw_ports
        configurations['interfaces'] = num_interfaces
        configurations['floating_ips'] = num_floating_ips
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Quantum server does not support state report."
                       " State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def main():
    #Hareesh
    #eventlet.monkey_patch()
    conf = cfg.CONF
    conf.register_opts(L3NATAgent.OPTS)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    conf(project='quantum')
    config.setup_logging(conf)
    server = quantum_service.Service.create(
        binary='quantum-l3-cfg-agent',
        topic=cl3_constants.L3_CFG_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='quantum.plugins.cisco.l3.agent.l3_cfg_agent.L3NATAgentWithStateReport')
    service.launch(server).wait()
