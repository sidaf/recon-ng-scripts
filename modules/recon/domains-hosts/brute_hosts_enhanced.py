from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
from recon.mixins.threads import ThreadingMixin
import dns.resolver
import os

class Module(BaseModule, ResolverMixin, ThreadingMixin):

    meta = {
        'name': 'DNS Hostname Brute Forcer',
        'author': 'Tim Tomes (@LaNMaSteR53)',
        'description': 'Brute forces host names using DNS. Updates the \'hosts\' table with the results.',
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        'options': (
            ('wordlist', os.path.join(BaseModule._home, 'data/', 'hostnames.txt'), True, 'path to hostname wordlist'),
            ('filter', False, True, 'if true a result is only added if the address returned already exists within the hosts table'),
        ),
    }

    def module_run(self, domains):
        with open(self.options['wordlist']) as fp:
            words = fp.read().split()
        resolver = self.get_resolver()
        for domain in domains:
            self.heading(domain, level=0)
            wildcard = None
            try:
                answers = resolver.query('*.%s' % (domain))
                wildcard = answers.response.answer[0][0]
                self.output('Wildcard DNS entry found for \'%s\' at \'%s\'.' % (domain, wildcard))
            except (dns.resolver.NoNameservers, dns.resolver.Timeout):
                self.error('Invalid nameserver.')
                continue
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                self.verbose('No Wildcard DNS entry found.')
            self.thread(words, domain, resolver, wildcard)

    def module_thread(self, word, domain, resolver, wildcard):
        word = word.lower()
        max_attempts = 3
        attempt = 0
        while attempt < max_attempts:
            host = '%s.%s' % (word, domain)
            try:
                answers = resolver.query(host)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                #self.verbose('%s => No record found.' % (host))
                blah = None
            except (dns.resolver.Timeout, dns.resolver.NoNameservers):
                attempt += 1
                if attempt >= max_attempts:
                    self.verbose('%s => Request timed out.' % (host))
                continue
            except (dns.name.EmptyLabel):
                continue
            else:
                # process answers
                if answers.response.answer[0][0] == wildcard:
                    #self.verbose('%s => Response matches the wildcard.' % (host))
                    pass
                else:
                    for answer in answers.response.answer:
                        for rdata in answer:
                            if rdata.rdtype in (1, 5):
                                if rdata.rdtype == 1:
                                    address = rdata.address
                                    if self.options['filter']:
                                        ips = self.query("SELECT ip_address FROM hosts WHERE ip_address=?", (address,))
                                        if len(ips) == 0:
                                            continue
                                    self.alert('%s => (A) %s' % (host, address))
                                    self.add_hosts(host, address)
                                if rdata.rdtype == 5:
                                    cname = rdata.target.to_text()[:-1]
                                    self.alert('%s => (CNAME) %s' % (host, cname))
                                    self.add_hosts(cname)
                                    # add the host in case a CNAME exists without an A record
                                    self.add_hosts(host)
            # break out of the loop
            attempt = max_attempts
