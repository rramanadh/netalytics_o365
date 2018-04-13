import json
import traceback
from lib.action import Netalyticso365Action


class GenericRestAction(Netalyticso365Action):
    def run(self, method, endpointurl, queryString, data, baseurl, companyId):
        try:
            companyIdKey = companyId + '_office365'
            value = self.action_service.get_value(companyIdKey, local=False)
            if value:
                retrieved_data = json.loads(value)
                access_token = retrieved_data.get('accessToken', '')
                if access_token:
                    return self.doRequest(baseurl, method, endpointurl, queryString, data, access_token, companyId)
                else:
                    return False, "Unable to retreive access_token for:%s" % companyId
            else:
                print "Unable to load credentials for:%s" % companyId
                return False, "Unable to load credentials for:%s" % companyId
        except Exception, e:
            print "Exception:%s TB:%s" % (e, traceback.format_exc())
            return False, "Exception in processing O365 Rest Action"