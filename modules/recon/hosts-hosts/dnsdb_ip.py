from recon.core.module import BaseModule
import StringIO
import json
import time

class Module(BaseModule):

    meta = {
        'name': 'Farsight DNS Database Hostname Lookup By IP Address',
        'author': 'Sion Dafydd',
        'description': 'Leverages the Farsight DNS database to retrieve hostnames recorded against each IP address. Updates the \'hosts\' table with the results.',
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL',
    }

    def module_run(self, hosts):
        for host in hosts:
            url = 'https://ea8xmom64f.execute-api.us-west-2.amazonaws.com/prod/dnsdb/lookup/rdata/ip/%s' % (host)
            headers = {'Accept': 'application/json'}
            resp = self.request(url, headers=headers)
            if "not authorized to access" in resp.text:
                jsonobj = json.loads(resp.text)
                self.output(jsonobj['Message'])
                break
            if "no results found for query" in resp.text:
                continue
            data = StringIO.StringIO(resp.text)
            for line in data:
                jsonobj = json.loads(line)
                hostname = str(jsonobj['rrname'])[:-1] # slice the trailing dot
                self.add_hosts(ip_address=host, host=hostname)

