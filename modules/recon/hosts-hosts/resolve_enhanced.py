from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
import dns.resolver

class Module(BaseModule, ResolverMixin):

    meta = {
        'name': 'Hostname Resolver',
        'author': 'Tim Tomes (@LaNMaSteR53)',
        'description': 'Resolves the IP address for a host. Updates the \'hosts\' table with the results.',
        'comments': (
            'Note: Nameserver must be in IP form.',
        ),
        'query': 'SELECT DISTINCT host FROM hosts WHERE host IS NOT NULL AND ip_address IS NULL',
        'options': (
            ('filter', True, True, 'if true results are only added if the address returned already exists within the hosts table'),
        ),
    }

    def module_run(self, hosts):
        q = self.get_resolver()
        for host in hosts:
            try:
                answers = q.query(host)
            except dns.resolver.NXDOMAIN:
                self.verbose('%s => The DNS query name does not exist' % (host))
            except dns.resolver.NoAnswer:
                self.verbose('%s => The DNS response does not contain an answer to the question' % (host))
            except (dns.resolver.NoNameservers):
                self.verbose('%s => All nameservers failed to answer the query' % (host))
            except (dns.resolver.Timeout):
                self.verbose('%s => The DNS operation timed out' % (host))
            else:
                for i in range(0, len(answers)):
                    if i == 0:
                        ip_address = answers[i].address
                        if self.options['filter']:
                            ips = self.query("SELECT ip_address FROM hosts WHERE ip_address=?", (ip_address,))
                            if len(ips) == 0:
                                continue
                        self.query('UPDATE hosts SET ip_address=? WHERE host=? AND ip_address IS NULL', (ip_address, host))
                    else:
                        ip_address = answers[i].address
                        if self.options['filter']:
                            ips = self.query("SELECT ip_address FROM hosts WHERE ip_address=?", (ip_address,))
                            if len(ips) == 0:
                                continue
                        data = {
                            'host': self.to_unicode(host),
                            'ip_address': self.to_unicode(answers[i].address)
                        }
                        self.insert('hosts', data, data.keys())
                    self.output('%s => %s' % (host, answers[i].address))
