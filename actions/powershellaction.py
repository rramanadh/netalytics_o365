import json
import traceback
from lib.action import Netalyticso365Action


class GenericRestAction(Netalyticso365Action):
    def run(self, method, endpointurl, queryString, data, companyId, updateCreds):
        try:
            powershellurl = 'https://cconsole.azurewebsites.net/api/HttpTriggerPowerShell1?code=zuzIeVijuKY1nt05/wgdT1Sr3LDS9XTfYTRrbB2yf/bErY8xrT18KA=='
            powershellbase_url = self.config.get('powershell_url', powershellurl)
            if updateCreds or companyId:
                companyIdKey = companyId + '_office365'
                value = self.action_service.get_value(companyIdKey, local=False)
                if value:
                    retrieved_data = json.loads(value)
                    username = retrieved_data.get('username', '')
                    password = retrieved_data.get('password', '')
                    data = data.encode('ascii', 'ignore') if isinstance(data, unicode) else data
                    if isinstance(data, str):
                        data = json.loads(data)
                    data['username'] = username
                    data['password'] = password
                else:
                    print "Unable to load credentials for:%s" % companyId
            return self.doRequest(powershellbase_url, method, endpointurl, queryString, data)
        except Exception, e:
            print "Exception:%s TB:%s" % (e, traceback.format_exc())
            return False, "Exception in processing O365 Power Shell Action"