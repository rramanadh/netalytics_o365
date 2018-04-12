from lib.action import Netalyticso365Action


class GenericRestAction(Netalyticso365Action):
    def run(self, method, endpointurl, queryString, data, baseurl):
        try:
            return self.doRequest(baseurl, method, endpointurl, queryString, data)
        except Exception, e:
            print "Exception:%s" % e
            return False, "Exception"