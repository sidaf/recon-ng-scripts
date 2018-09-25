from recon.core.module import BaseModule
import json

class Module(BaseModule):

    meta = {
        'name': 'Censys.io Port Hostname Enumerator by Domain',
        'author': 'Sion Dafydd',
        'description': 'Harvests hostname information from the Censys IO API. Updates the \'hosts\' table with the results.',
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
    }

    def module_run(self, hosts):
        api_id = self.get_key('censysio_id')
        api_secret = self.get_key('censysio_secret')
        base_url = 'https://censys.io/api/v1/search/certificates'
        for host in hosts:
            payload = json.dumps({'query': 'parsed.names:%s' % host})
            resp = self.request(base_url, payload=payload, auth=(api_id, api_secret), method='POST', content='JSON')
            if resp.status_code == 200:
                pages = resp.json['metadata']['pages']
                for element in resp.json['results']:
                    fingerprint = element['parsed.fingerprint_sha256']
                    vbase_url = 'https://censys.io/api/v1/view/certificates/%s' % fingerprint
                    vresp = self.request(vbase_url, auth=(api_id, api_secret), method='GET')
                    if vresp.status_code == 200:
                        for name in vresp.json['parsed']['names']:
                            if name.startswith('*'):
                                continue
                            self.add_hosts(ip_address=None, host=name.lower())
                    elif vresp.status_code == 429:
                        self.output(vresp.json['error'])
                        return
                if pages > 1:
                    for i in range(pages)[1:]:
                        page_id = i + 1
                        payload = json.dumps({'page': page_id, 'query': 'parsed.names:%s' % host})
                        resp = self.request(base_url, payload=payload, auth=(api_id, api_secret), method='POST', content='JSON')
                        if resp.status_code == 200:
                            for element in resp.json['results']:
                                fingerprint = element['parsed.fingerprint_sha256']
                                vbase_url = 'https://censys.io/api/v1/view/certificates/%s' % fingerprint
                                vresp = self.request(vbase_url, auth=(api_id, api_secret), method='GET')
                                if vresp.status_code == 200:
                                    for name in vresp.json['parsed']['names']:
                                        if name.startswith('*'):
                                            continue
                                        self.add_hosts(ip_address=None, host=name.lower())
                                elif vresp.status_code == 429:
                                    self.output(vresp.json['error'])
                                    return
            elif resp.status_code == 429:
                self.output(resp.json['error'])
                return
