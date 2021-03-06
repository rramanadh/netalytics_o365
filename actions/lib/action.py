import json
import urllib
import xmldict
import requests
import traceback
import azure.common.credentials
import xml.etree.ElementTree as ET
from st2common.runners.base_action import Action


class Netalyticso365Action(Action):
    def __init__(self, config):
        super(Netalyticso365Action, self).__init__(config)
        self.params = None
        self.accesstoken = ''

    def handleRequestAuth(self, headers):
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        if self.accesstoken:
            headers["Authorization"] = 'Bearer {0}'.format(self.accesstoken)

    def buildQuery(self, url, query=None):
        if query is not None and query:
            if isinstance(query, dict):
                url += "?" + urllib.urlencode(query)
            else:
                url += "?" + query
        return url

    def refreshToken(self, companyId):
        companyIdKey = companyId + '_office365'
        value = self.action_service.get_value(companyIdKey, local=False)
        accessToken = ""
        if value:
            credsData = json.loads(value)
            credentials = azure.common.credentials.ServicePrincipalCredentials(
                client_id=str(credsData.get("graphClientId", "")),
                secret=str(credsData.get("graphClientSecret", "")),
                tenant=str(credsData.get("DefaultDomainName", "")),
                resource='https://graph.windows.net'
            )
            token_response = credentials.__dict__
            if "token" in token_response and "access_token" in token_response["token"]:
                credsData['accessToken'] = token_response['token'].get('access_token')
                accessToken = credsData['accessToken']
            self.action_service.set_value(name=companyIdKey, value=json.dumps(credsData), local=False)
        return accessToken

    def getToken(self, companyId):
        companyIdKey = companyId + '_office365'
        value = self.action_service.get_value(companyIdKey, local=False)
        accessToken = ""
        if value:
            try:
                retrieved_data = json.loads(value)
                accessToken = retrieved_data.get('accessToken', '')
            except Exception, e:
                print "Exception in getting accesstoken:%s" % e
        return accessToken

    def doRequest(self, base_url, method, endpointURL, queryString=None, data=None, access_token='', companyId=''):
        self.method = method
        self.companyId = companyId
        self.accesstoken = access_token
        self.endpointURL = base_url + endpointURL
        self.queryString = queryString
        self.data = data.encode('ascii', 'ignore') if isinstance(data, unicode) else data
        if companyId and len(self.accesstoken) == 0:
            self.accesstoken = self.getToken(self.companyId)
            if len(self.accesstoken):
                self.accesstoken = self.refreshToken(companyId)

        try:
            headers = {'Content-Length': '0'}
            self.handleRequestAuth(headers)
            finalUrl = self.buildQuery(url=self.endpointURL, query=queryString)
            if 'params' in finalUrl:
                self.params = finalUrl['params']
            else:
                self.endpointURL = finalUrl
            if self.data:
                headers['Content-Length'] = str(len(json.dumps(self.data)) if not isinstance(self.data, basestring) else len(self.data))

            # Validating the url
            if not self.endpointURL.startswith("http://") and not self.endpointURL.startswith("https://"):
                while self.endpointURL.startswith("/"):
                    self.endpointURL = self.endpointURL[1:]
                self.endpointURL = "https://%s" % self.endpointURL
            resp = getattr(requests, self.method.lower())(self.endpointURL,
                                                          data=json.dumps(self.data) if data and not isinstance(self.data, basestring) else self.data,
                                                          params=self.params,
                                                          headers=headers, verify=False)
            text = resp.text
            # logger.info('Links: '+ str(resp.links))
            if int(resp.status_code / 100) == 2:
                try:
                    if 'Content-Type' in resp.headers and ('text/xml' in resp.headers['Content-Type'] or 'application/xml' in resp.headers['Content-Type']):
                        text = self.convertUnicodeToString(text)
                        return True, xmldict.xml_to_dict(text.replace('xmlns', 'x'))
                    data = json.loads(text) if text and text.strip() else {}

                    if endpointURL == "events" and len(data.get('data', {})):
                        data['data'] = self.convertLongToString(data['data'])

                    if "msg" in data and "msg" in data["msg"]:
                        data = data["msg"]["msg"]
                    elif 'msg' in data:
                        data = data['msg']
                    #elif "items" in data:
                    #    data = data['items']
                    if isinstance(data, dict):
                        data['pageLinkDetails'] = resp.links
                    return True, data
                except Exception as e:
                    x = dict()
                    x["ErrorCode"] = 503
                    x["ErrorString"] = traceback.format_exc()
                    print x["ErrorString"]
                    return False, x
            elif int(resp.status_code) == 401:
                access_token = self.refreshToken(companyId)
                if len(access_token) == 0:
                    return False, "Error in Access Token"
                return self.doRequest(base_url, method, endpointURL, queryString, data, access_token)
            try:
                # Checking if response is in XML
                try:
                    text = self.convertUnicodeToString(text)
                    ET.fromstring(text)
                    return False, {'status': resp.status_code, 'msg': self.awsErrorResp(xmldict.xml_to_dict(text.replace('xmlns', 'x')))}
                except Exception, e:
                    pass

                text = json.loads(text) if text and text.strip() else ""
                if isinstance(text, dict):
                    errData = []
                    for k, v in text.items():
                        if isinstance(v, list):
                            errData.extend(v)
                        elif isinstance(v, str) or isinstance(v, unicode):
                            errData.append(v)
                    text = errData
                if isinstance(text, list):
                    return False, {'status': resp.status_code, 'msg': " ".join(text)}
            except Exception as e:
                pass
            return False, {'status': resp.status_code, 'msg': str(text) if not isinstance(text, str) else text}
        except Exception as e:
            x = dict()
            x["ErrorCode"] = 503
            x["ErrorString"] = str(e)
            x['trace'] = traceback.format_exc()
            return False, x
