# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
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
# @author: Kyle Mestery, Cisco Systems, Inc.
# @author: Lorand Jakab, Cisco Systems, Inc.

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy.orm import exc as sa_exc

from neutron.common import exceptions as exc
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

LISP_UDP_PORT = 4341
MAX_LISP_IID = 16777215

lisp_opts = [
    cfg.ListOpt('iid_ranges',
                default=[],
                help=_("Comma-separated list of <iid_min>:<iid_max> tuples "
                       "enumerating ranges of LISP IIDs that are "
                       "available for tenant network allocation")),
]

cfg.CONF.register_opts(lisp_opts, "ml2_type_lisp")


class LispAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_lisp_allocations'

    lisp_iid = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False)


class LispEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""
    __tablename__ = 'ml2_lisp_endpoints'

    ip_address = sa.Column(sa.String(64), primary_key=True)
    udp_port = sa.Column(sa.Integer, primary_key=True, nullable=False,
                         autoincrement=False)

    def __repr__(self):
        return "<LispTunnelEndpoint(%s)>" % self.ip_address


class LispTypeDriver(type_tunnel.TunnelTypeDriver):

    def get_type(self):
        return p_const.TYPE_LISP

    def initialize(self):
        self.lisp_iid_ranges = []
        self._parse_tunnel_ranges(
            cfg.CONF.ml2_type_lisp.iid_ranges,
            self.lisp_iid_ranges,
            p_const.TYPE_LISP
        )
        self._sync_lisp_allocations()

    def reserve_provider_segment(self, session, segment):
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(LispAllocation).
                         filter_by(lisp_iid=segmentation_id).
                         with_lockmode('update').
                         one())
                if alloc.allocated:
                    raise exc.TunnelIdInUse(tunnel_id=segmentation_id)
                LOG.debug(_("Reserving specific lisp tunnel %s from pool"),
                          segmentation_id)
                alloc.allocated = True
            except sa_exc.NoResultFound:
                LOG.debug(_("Reserving specific lisp tunnel %s outside pool"),
                          segmentation_id)
                alloc = LispAllocation(lisp_iid=segmentation_id)
                alloc.allocated = True
                session.add(alloc)

    def allocate_tenant_segment(self, session):
        with session.begin(subtransactions=True):
            alloc = (session.query(LispAllocation).
                     filter_by(allocated=False).
                     with_lockmode('update').
                     first())
            if alloc:
                LOG.debug(_("Allocating lisp tunnel IID %(lisp_iid)s"),
                          {'lisp_iid': alloc.lisp_iid})
                alloc.allocated = True
                return {api.NETWORK_TYPE: p_const.TYPE_LISP,
                        api.PHYSICAL_NETWORK: None,
                        api.SEGMENTATION_ID: alloc.lisp_iid}

    def release_segment(self, session, segment):
        lisp_iid = segment[api.SEGMENTATION_ID]
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(LispAllocation).
                         filter_by(lisp_iid=lisp_iid).
                         with_lockmode('update').
                         one())
                alloc.allocated = False
                for low, high in self.lisp_iid_ranges:
                    if low <= lisp_iid <= high:
                        LOG.debug(_("Releasing lisp tunnel %s to pool"),
                                  lisp_iid)
                        break
                else:
                    session.delete(alloc)
                    LOG.debug(_("Releasing lisp tunnel %s outside pool"),
                              lisp_iid)
            except sa_exc.NoResultFound:
                LOG.warning(_("lisp_iid %s not found"), lisp_iid)

    def _sync_lisp_allocations(self):
        """
        Synchronize lisp_allocations table with configured tunnel ranges.
        """

        # determine current configured allocatable iids
        lisp_iids = set()
        for tun_min, tun_max in self.lisp_iid_ranges:
            if tun_max + 1 - tun_min > MAX_LISP_IID:
                LOG.error(_("Skipping unreasonable LISP IID range "
                            "%(tun_min)s:%(tun_max)s"),
                          {'tun_min': tun_min, 'tun_max': tun_max})
            else:
                lisp_iids |= set(xrange(tun_min, tun_max + 1))

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            # remove from table unallocated tunnels not currently allocatable
            allocs = session.query(LispAllocation)
            for alloc in allocs:
                try:
                    # see if tunnel is allocatable
                    lisp_iids.remove(alloc.lisp_iid)
                except KeyError:
                    # it's not allocatable, so check if its allocated
                    if not alloc.allocated:
                        # it's not, so remove it from table
                        LOG.debug(_("Removing tunnel %s from pool"),
                                  alloc.lisp_iid)
                        session.delete(alloc)

            # add missing allocatable tunnels to table
            for lisp_iid in sorted(lisp_iids):
                alloc = LispAllocation(lisp_iid=lisp_iid)
                session.add(alloc)

    def get_lisp_allocation(self, session, lisp_iid):
        with session.begin(subtransactions=True):
            return session.query(LispAllocation).filter_by(
                lisp_iid=lisp_iid).first()

    def get_endpoints(self):
        """Get every lisp endpoints from database."""

        LOG.debug(_("get_lisp_endpoints() called"))
        session = db_api.get_session()

        with session.begin(subtransactions=True):
            lisp_endpoints = session.query(LispEndpoints)
            return [{'ip_address': lisp_endpoint.ip_address,
                     'udp_port': lisp_endpoint.udp_port}
                    for lisp_endpoint in lisp_endpoints]

    def add_endpoint(self, ip, udp_port=LISP_UDP_PORT):
        LOG.debug(_("add_lisp_endpoint() called for ip %s"), ip)
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            try:
                lisp_endpoint = (session.query(LispEndpoints).
                                  filter_by(ip_address=ip).
                                  with_lockmode('update').one())
            except sa_exc.NoResultFound:
                lisp_endpoint = LispEndpoints(ip_address=ip,
                                                udp_port=udp_port)
                session.add(lisp_endpoint)
            return lisp_endpoint
