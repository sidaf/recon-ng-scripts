from recon.core.module import BaseModule
from urlparse import urlparse
import re

class Module(BaseModule):

    meta = {
        'name': 'Retrive Netblock Via Whois',
        'author': 'Sion Dafydd, based on orginal script by Zach Grace (@ztgrace)',
        'description': 'Uses the ARIN/RIPE Whois to get the netblock and company for an IP address',
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL',
    }

    def get_orgRef(self, resp):
        try:
            handle = resp.json['ns4:pft']['net']['orgRef']['@handle']
        except KeyError:
            return None
        return handle

    def process_arin(self, ip, resp):
        try: # Reallocated IP space
            org = resp.json['ns4:pft']['customer']['name']['$']
            handle = resp.json['ns4:pft']['customer']['handle']['$']
        except KeyError, ke:
            try: # Direct allocation
                org = resp.json['ns4:pft']['net']['orgRef']['@name']
                handle = resp.json['ns4:pft']['net']['orgRef']['@handle']
            except KeyError, ke:
                self.output("Error querying %s" % ip)
                return

        self.add_companies(company=org, description=handle)

        netblocks = resp.json['ns4:pft']['net']['netBlocks']['netBlock']
        if type(netblocks) == dict: # single net block
            netblock = resp.json['ns4:pft']['net']['netBlocks']['netBlock']
            cidr = netblock['cidrLength']['$']
            description = netblock['description']['$']
            endAddress = netblock['endAddress']['$']
            startAddress = netblock['startAddress']['$']
            nb = "%s/%s" % (startAddress, cidr)
            self.verbose("%s is in netblock %s and belongs to %s" % (ip, nb, org))
            self.add_netblocks(nb)
        elif type(netblocks) == list: # multiple netblocks
            for netblock in netblocks:
                cidr = netblock['cidrLength']['$']
                description = netblock['description']['$']
                endAddress = netblock['endAddress']['$']
                startAddress = netblock['startAddress']['$']
                nb = "%s/%s" % (startAddress, cidr)
                self.verbose("%s is in netblock %s and belongs to %s" % (ip, nb, org))
                self.add_netblocks(nb)

    def retrieve_ripe(self, ip):
        headers = {'Accept': 'application/json'}
        url = 'https://rest.db.ripe.net/search.json?query-string=%s' % ip
        resp = self.request(url, headers=headers)
        if resp.status_code == 200:
            route = None
            descr = None
            objects = resp.json['objects']['object']
            for obj in objects:
                if obj['type'] == 'route':
                    attributes = obj['attributes']['attribute']
                    for att in attributes:
                        if att['name'] == 'route':
                            route = att['value'];
                        if att['name'] == 'descr':
                           descr = att['value'];
                    break;
            if route:
                self.verbose("%s is in netblock %s and belongs to %s" % (ip, route, descr))
                self.add_netblocks(route)
                self.add_companies(company=descr)
        else:
            self.output("%s HTTP status code received from server" % resp.status_code)

    def module_run(self, ips):
        headers = {'Accept': 'application/json'}
        url = 'http://whois.arin.net/ui/query.do'
        for ip in ips:
            payload = {'flushCache': 'false', 'q': ip}
            resp = self.request(url, headers=headers, payload=payload)

            if self.get_orgRef(resp) == 'ARIN':
                self.process_arin(ip, resp)
            elif self.get_orgRef(resp) == 'RIPE':
                self.retrieve_ripe(ip)
            else:
                self.output('%s is registered with the %s' % (ip, resp.json['ns4:pft']['net']['orgRef']['@name']))

