from lib.action import Netalyticso365Action


class GenericRestAction(Netalyticso365Action):
    def run(self, method, endpointurl, queryString, data):
        try:
            base_url = self.config.get('base_url', 'https://graph.microsoft.com/v1.0/')
            return self.doRequest(base_url, method, endpointurl, queryString, data)
        except Exception, e:
            print "Exception:%s" % e
            return False, "Exception"