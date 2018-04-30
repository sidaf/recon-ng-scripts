from recon.core.module import BaseModule
import StringIO
import json
import time

class Module(BaseModule):

    meta = {
        'name': 'Farsight DNS Database Sub-domain Lookup',
        'author': 'Sion Dafydd',
        'description': 'Leverages the Farsight DNS database to retrieve sub-domains recorded against each domain. Updates the \'hosts\' table with the results.',
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        'options': (
            ('filter', False, True, 'if true results are only added if the address returned already exists within the hosts table'),
        ),
    }

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)

            url = 'https://ea8xmom64f.execute-api.us-west-2.amazonaws.com/dev/dnsdb/lookup/rrset/name/*.%s' % (domain)
            headers = {'Accept': 'application/json'}
            max_attempts = 3
            attempt = 0
            while attempt < max_attempts:
                try:
                    resp = self.request(url, headers=headers)
                except SSLError:
                    attempt += 1
                    if attempt >= max_attempts:
                        self.error('Request timed out.')
                    continue
                break
            if "no results found for query" in resp.text:
                self.output('No results found.')
                continue
            data = StringIO.StringIO(resp.text)
            for line in data:
                jsonobj = json.loads(line)
                rrtype = str(jsonobj['rrtype'])
                hostname = str(jsonobj['rrname'])[:-1] # slice the trailing dot
                if rrtype ==  "A":
                    ip_address = str(jsonobj['rdata'][0])
                    if self.options['filter']:
                        ips = self.query("SELECT ip_address FROM hosts WHERE ip_address=?", (ip_address,))
                        if len(ips) == 0:
                            continue
                    self.add_hosts(ip_address=ip_address, host=hostname)
                elif rrtype == "CNAME":
                    cname = str(jsonobj['rdata'][0])[:-1]
                    self.add_hosts(cname)
                    # add the host in case a CNAME exists without an A record
                    self.add_hosts(hostname)
                else:
                    self.output('%s => (%s) %s' % (hostname, rrtype, ", ".join(jsonobj['rdata'])))

