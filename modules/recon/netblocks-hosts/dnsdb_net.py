from recon.core.module import BaseModule
import StringIO
import json
import time

class Module(BaseModule):

    meta = {
        'name': 'Farsight DNS Database Hostname Lookup By Netblock',
        'author': 'Sion Dafydd',
        'description': 'Leverages the Farsight DNS database to retrieve hostnames recorded against each IP address in a netblock. Updates the \'hosts\' table with the results.',
        'query': 'SELECT DISTINCT netblock FROM netblocks WHERE netblock IS NOT NULL',
    }

    def module_run(self, netblocks):
        for netblock in netblocks:
            url = 'https://ea8xmom64f.execute-api.us-west-2.amazonaws.com/dev/dnsdb/lookup/rdata/ip/%s' % (netblock.replace("/", ","))
            headers = {'Accept': 'application/json'}
            resp = self.request(url, headers=headers)
            if "no results found for query" in resp.text:
                continue
            data = StringIO.StringIO(resp.text)
            for line in data:
                jsonobj = json.loads(line)
                ipaddress = str(jsonobj['rdata'])
                hostname = str(jsonobj['rrname'])[:-1] # slice the trailing dot
                self.add_hosts(ip_address=ipaddress, host=hostname)

