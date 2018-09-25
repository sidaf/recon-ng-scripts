from recon.core.module import BaseModule
import json

class Module(BaseModule):

    meta = {
        'name': 'Censys.io Port Enumerator',
        'author': 'Sion Dafydd, based on a script by ScumSec 0x1414',
        'description': 'Harvests port information from the Censys IO API. Updates the \'ports\' table with the results.',
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE host IS NOT NULL',
    }

    def module_run(self, hosts):
        api_id = self.get_key('censysio_id')
        api_secret = self.get_key('censysio_secret')
        base_url = 'https://censys.io/api/v1/search/ipv4'
        for host in hosts:
            #self.heading(host, level=0)
            payload = json.dumps({'query': '%s' % host})
            resp = self.request(base_url, payload=payload, auth=(api_id, api_secret), method='POST', content='JSON')
            # print resp.json
            if resp.status_code == 200:
                pages = resp.json['metadata']['pages']
                for element in resp.json['results']:
                    ip_address = element['ip']
                    for protocol in element['protocols']:
                        port, service = protocol.split('/')
                        #self.add_ports(ip_address=ip_address, host=host, port=port, protocol=service)
                        self.add_ports(ip_address=ip_address, port=port, protocol=service)
                if pages > 1:
                    for i in range(pages)[1:]:
                        page_id = i + 1
                        payload = json.dumps({'page': page_id, 'query': 'a:%s' % host})
                        resp = self.request(base_url, payload=payload, auth=(api_id, api_secret), method='POST', content='JSON')
                        if resp.status_code == 200:
                            for element in resp.json['results']:
                                ip_address = element['ip']
                                for protocol in element['protocols']:
                                    port, service = protocol.split('/')
                                    #self.add_ports(ip_address=ip_address, host=host, port=port, protocol=service)
                                    self.add_ports(ip_address=ip_address, port=port, protocol=service)

            elif resp.status_code == 429:
                self.output(resp.json['error'])
                break
            #else:
            #    self.output('%s => Bad request!' % host)
