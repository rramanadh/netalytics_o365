import json
import datetime
import traceback
from copy import deepcopy
from pymongo import MongoClient
from lib.action import Netalyticso365Action


class Remapper:
    def getSignInName(self, signInList):
        if len(signInList) > 0:
            for user in signInList:
                if user["type"] == "emailAddress":
                    return user["value"]
        else:
            return ""

    def getLicenses(self, skuList):
        licenseList = []
        if len(skuList) > 0 and len(self.Licenses) > 0:
            for sku in skuList:
                for lic in self.Licenses:
                    if sku["skuId"] == lic["skuId"]:
                        lic["AccountSkuId"] = lic["SkuPartNumber"]
                        licenseList.append({"AccountSku": lic})
        return licenseList

    def getSecurityGroupData(self, data):
        grpList = []
        for doc in data:
            grpData = {"formatEntryInfo": {"listViewFieldList": []}}
            for (k, v) in doc.items():
                grpData["formatEntryInfo"]["listViewFieldList"].append(
                    {"label": None, "propertyName": k, "formatPropertyField": {"propertyValue": v, "alignment": 0}})
            grpList.append(grpData)
        return grpList

    def mapObject(self, inputList, mapper):
        isDict = False
        if type(inputList) is dict:
            isDict = True
            inputList = [inputList]
        outputList = []
        for input in inputList:
            output = dict()
            for (k, v) in mapper.iteritems():
                m = v.split(':')
                function = None
                if len(m) > 1:
                    function = m[1]
                # handle duplicate keys in json
                k = k.split("$$$")[0]

                keys = k.split(".")
                y = ""
                for x in keys:
                    y += "[\"" + x + "\"]"
                # print y
                try:
                    value = eval("input" + y)
                    if function:
                        # print function
                        function = function.replace("$value", str(value))
                        # print function
                        value = eval(function)
                    # handle None keys in json
                    if value == None:
                        value = ""
                    if value == 'none':
                        value = None
                        # Handle Inner keys
                    keySplit = m[0].split(".")
                    if len(keySplit) > 1:
                        if not output.has_key(keySplit[0]):
                            output[keySplit[0]] = {}
                        output[keySplit[0]][keySplit[1]] = value
                    else:
                        output[m[0]] = value
                        # output[m[0]]=value
                        #                except(KeyError,e):
                        #                    logger.error("Input key",y,"not found")
                        #
                except Exception, e:
                    print("Input key" + y + "not found")
            outputList.append(output)
        if isDict:
            return outputList[0]
        return outputList


def getUtcTime(convertDate=None, resetSeconds=False):
    if convertDate is None:
        convertDate = datetime.datetime.utcnow()
    else:
        try:
            convertDate = int(convertDate)
        except Exception as e:
            pass
        if isinstance(convertDate, int):
            convertDate = datetime.datetime.fromtimestamp(convertDate)
    try:
        if resetSeconds:
            return int(convertDate.replace(second=0).strftime("%s"))
        else:
            return int(convertDate.strftime("%s"))
    except Exception as e:
        return int(datetime.datetime.utcnow().replace(second=0).strftime("%s"))


class O365Sync(Netalyticso365Action):
    def run(self, partnerId, companyId):
        pymongoconn = MongoClient("172.31.8.235", 27017)
        db = pymongoconn['ciscostandalone']
        query = {"partnerId": partnerId, "companyId": companyId}
        powershellurl = 'https://cconsole.azurewebsites.net/api/HttpTriggerPowerShell1?code=zuzIeVijuKY1nt05/wgdT1Sr3LDS9XTfYTRrbB2yf/bErY8xrT18KA=='
        powershellbase_url = self.config.get('powershell_url', powershellurl)

        # Getting the credentials information from datastore
        companyIdKey = companyId + '_office365'
        value = self.action_service.get_value(companyIdKey, local=False)
        if value:
            try:
                retrieved_data = json.loads(value)
                access_token = retrieved_data.get('accessToken', '')
                if not access_token:
                    return False, "Unable to retreive access_token"
            except Exception, e:
                return False, "Exception in getting data from datastore Exception:%s TB:%s" % (
                e, traceback.format_exc())
        else:
            print "Unable to find companyId"
            return False, "Unable to find companyId"

        restbase_url = "https://graph.windows.net/" + retrieved_data['DefaultDomainName'] + '/'
        queryString = "api-version=1.6"
        username = retrieved_data.get("username", "")
        password = retrieved_data.get("password", "")

        # syncing the users
        (status, resp) = self.doRequest(restbase_url, "GET", "/users", queryString=queryString,
                                        access_token=access_token, companyId=companyId)
        if status:
            userscoll = db['o365_users']
            userdata = resp['value']
            usersMapping = {"userPrincipalName": "UserPrincipalName", "displayName": "DisplayName",
                            "givenName": "FirstName",
                            "surname": "LastName", "accountEnabled": "BlockCredential:not bool($value)",
                            "passwordPolicies": "PasswordNeverExpires:True if \'$value\'==\'DisablePasswordExpiration\' else False",
                            "objectType": "CloudExchangeRecipientDisplayType", "otherMails": "AlternateEmailAddresses",
                            "city": "City", "country": "Country",
                            "usageLocation": "UsageLocation", "proxyAddresses": "ProxyAddresses",
                            "signInNames": "SignInName:self.getSignInName($value)",
                            "lastDirSyncTime": "LastDirSyncTime", "objectId": "ObjectId",
                            "preferredLanguage": "PreferredLanguage", "mail": "Mail",
                            "department": "Department", "userType": "UserType", "passwordProfile.password": "PassWord",
                            "passwordProfile.forceChangePasswordNextLogin": "ForceChangePassword",
                            "assignedLicenses$$$": "Licenses:self.getLicenses($value)",
                            "assignedLicenses": "IsLicensed:True if len($value) > 0 else False"}
            r = Remapper()
            (status, skudata) = self.doRequest(restbase_url, "GET", "/subscribedSkus", queryString=queryString,
                                            access_token=access_token, companyId=companyId)
            if status:
                r.Licenses = skudata['value']
                resp = r.mapObject(userdata, usersMapping)

                for data in resp:
                    dataid = data['ObjectId']
                    q = deepcopy(query)
                    q['ObjectId'] = dataid
                    findresp = userscoll.find_one(q)
                    if findresp is None:
                        data['partnerId'] = partnerId
                        data['companyId'] = companyId
                        data['created'] = getUtcTime()
                        data['updated'] = getUtcTime()
                        userscoll.insert(data)
                    else:
                        userscoll.update({"_id": findresp['_id']}, data)
            else:
                print "Failed to get users subscribedSkus"
        else:
            print "Failed to get users"

        # syncing the groups
        data = {"isoffice": True,
                "query1": "$getMsol=Get-MsolUser -All  | select DisplayName, FirstName,LastName,UserPrincipalName,IsLicensed,Licenses,ProxyAddresses | ConvertTo-Json -Compress \n if($getMsol -eq $Null){ConvertTo-Json @()}else{$getMsol}",
                "query2": "$getMsolDomain = Get-MsolDomain  -ErrorAction SilentlyContinue | select Name , Status , Authentication | ConvertTo-Json -Compress \n if($getMsolDomain -eq $Null){ConvertTo-Json @()}else{$getMsolDomain}",
                "query3": "$getDist = Get-DistributionGroup -Filter '(RecipientTypeDetails -eq \"MailUniversalDistributionGroup,MailUniversalSecurityGroup\")' | select DisplayName ,Name,Alias,Identity, EmailAddresses,PrimarySmtpAddress,RecipientType,RecipientTypeDetails, GroupType, Type , WindowsEmailAddress , ManagedBy, Members,Notes,MemberJoinRestriction,MemberDepartRestriction, ExternalDirectoryObjectId,GUID | ConvertTo-Json -Depth 5 -Compress \n if($getDist -eq $Null){ConvertTo-Json @()}else{$getDist}"
                }
        data['username'] = username
        data['password'] = password
        (status, resp) = self.doRequest(powershellbase_url, "POST", "", data=json.dumps(data),
                                        access_token=access_token, companyId=companyId)
        if status:
            domgroups = db['o365_groups']
            data = resp['result3']
            for respdata in data:
                q = deepcopy(query)
                q['Guid'] = respdata['Guid']
                findresp = domgroups.find_one(q)
                if findresp is None:
                    respdata['partnerId'] = partnerId
                    respdata['companyId'] = companyId
                    respdata['created'] = getUtcTime()
                    respdata['updated'] = getUtcTime()
                    domgroups.insert(respdata)
                else:
                    domgroups.update({"_id": findresp['_id']}, respdata)

        # syncing the domains
        data = {"isoffice": False, "isDelegatedAdmin": False,
                "query1": "Get-MsolDomain | select Name , Status , Authentication | ConvertTo-Json -Compress"
                }
        data['username'] = username
        data['password'] = password
        (status, resp) = self.doRequest(powershellbase_url, "POST", "", data=json.dumps(data),
                                        access_token=access_token, companyId=companyId)
        if status:
            domcoll = db['o365_domains']
            data = resp['result1']
            for respdata in data:
                q = deepcopy(query)
                q['Name'] = respdata['Name']
                findresp = domcoll.find_one(q)
                if findresp is None:
                    respdata['partnerId'] = partnerId
                    respdata['companyId'] = companyId
                    respdata['created'] = getUtcTime()
                    respdata['updated'] = getUtcTime()
                    domcoll.insert(respdata)
                else:
                    domcoll.update({"_id": findresp['_id']}, respdata)

        # syncing the public folder mail boxes
        data = {"isoffice": True,
                "query1": "Get-Mailbox -PublicFolder | Select Name, Path ,Identity, DisplayName, EmailAddresses, PrimarySmtpAddress, EmailAddressPolicyEnabled, MaxSendSize, MaxReceiveSize | ConvertTo-Json -Compress"}
        data['username'] = username
        data['password'] = password
        (status, resp) = self.doRequest(powershellbase_url, "POST", "", data=json.dumps(data),
                                        access_token=access_token, companyId=companyId)
        if status:
            publicfoldermailboxes = db['o365_publicfolder_mailboxes']
            resp = resp['result1']
            for data in resp:
                q = deepcopy(query)
                q['PrimarySmtpAddress'] = data['PrimarySmtpAddress']
                findresp = publicfoldermailboxes.find_one(q)
                if findresp is None:
                    data['partnerId'] = partnerId
                    data['companyId'] = companyId
                    data['created'] = getUtcTime()
                    data['updated'] = getUtcTime()
                    publicfoldermailboxes.insert(data)
                else:
                    publicfoldermailboxes.update({"_id": findresp['_id']}, data)

        # syncing the public folders
        data = {"isoffice": True,
                "query1": "Get-PublicFolder -Recurse | Select Name, Path, Identity, MailEnabled, FolderSize, HasSubfolders | ConvertTo-Json -Compress"}
        data['username'] = username
        data['password'] = password
        (status, resp) = self.doRequest(powershellbase_url, "POST", "", data=json.dumps(data),
                                        access_token=access_token, companyId=companyId)
        if status:
            publicfolders = db['o365_publicfolders']
            resp = resp['result1']
            for data in resp:
                q = deepcopy(query)
                q['Name'] = data['Name']
                findresp = publicfolders.find_one(q)
                if findresp is None:
                    data['partnerId'] = partnerId
                    data['companyId'] = companyId
                    data['created'] = getUtcTime()
                    data['updated'] = getUtcTime()
                    publicfolders.insert(data)
                else:
                    publicfolders.update({"_id": findresp['_id']}, data)

        # syncing the shared mail boxes
        data = {"isoffice": True,
                "query1": "$getMailbox = Get-Mailbox -ErrorAction SilentlyContinue | select UserPrincipalName, Identity, FullAccess, SendAs, DisplayName, Alias, ServerName, HiddenFromAddressListsEnabled | ConvertTo-Json -Compress  \n if($getMailbox -eq $Null){ConvertTo-Json @()}else{$getMailbox} \n",
                "query2": "$getMailboxRecip = Get-Mailbox -ErrorAction SilentlyContinue -RecipientTypeDetails SharedMailbox | Select Name, UserPrincipalName, Identity, FullAccess, SendAs, DisplayName, Alias, ServerName, HiddenFromAddressListsEnabled  | ConvertTo-Json -Compress \n if($getMailboxRecip -eq $Null){ConvertTo-Json @()}else{$getMailboxRecip} \n"}
        data['username'] = username
        data['password'] = password
        (status, resp) = self.doRequest(powershellbase_url, "POST", "", data=json.dumps(data),
                                        access_token=access_token, companyId=companyId)
        if status:
            sharedmailboxes = db['o365_sharedmailboxes']
            resp = resp['result2']
            if isinstance(resp, dict):
                resp = [resp]
            for data in resp:
                q = deepcopy(query)
                q['UserPrincipalName'] = data['UserPrincipalName']
                findresp = sharedmailboxes.find_one(q)
                if findresp is None:
                    data['partnerId'] = partnerId
                    data['companyId'] = companyId
                    data['created'] = getUtcTime()
                    data['updated'] = getUtcTime()
                    sharedmailboxes.insert(data)
                else:
                    sharedmailboxes.update({"_id": findresp['_id']}, data)

        # syncing the mail contacts
        (status, resp) = self.doRequest(restbase_url, "GET", "/contacts", queryString=queryString,
                                        access_token=access_token, companyId=companyId)
        if status:
            contacts = resp['value']
            contactdb = db['o365_contacts']
            for data in contacts:
                q = deepcopy(query)
                q['objectId'] = data['objectId']
                data['type'] = data['odata.type']
                del data['odata.type']
                findresp = contactdb.find_one(q)
                if findresp is None:
                    data['partnerId'] = partnerId
                    data['companyId'] = companyId
                    data['created'] = getUtcTime()
                    data['updated'] = getUtcTime()
                    contactdb.insert(data)
                else:
                    contactdb.update({"_id": findresp['_id']}, data)
        else:
            print "Failed to get contacts"

        return True, "Sync completed"