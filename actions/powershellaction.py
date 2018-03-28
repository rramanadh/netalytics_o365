from lib.action import Netalyticso365Action


class GenericRestAction(Netalyticso365Action):
    def run(self, method, endpointurl, queryString, data):
        try:
            base_url = self.config.get('powershell_url', 'https://cconsole.azurewebsites.net/api/HttpTriggerPowerShell1?code=zuzIeVijuKY1nt05/wgdT1Sr3LDS9XTfYTRrbB2yf/bErY8xrT18KA==')
            return self.doRequest(base_url, method, endpointurl, queryString, data)
        except Exception, e:
            print "Exception:%s" % e
            return False, "Exception"