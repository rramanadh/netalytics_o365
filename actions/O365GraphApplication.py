import json
import azure.common.credentials
from lib.action import Netalyticso365Action


class O365GraphApplication(Netalyticso365Action):
    def run(self, partnerId, companyId, username, password, action):
        powershellurl = 'https://cconsole.azurewebsites.net/api/HttpTriggerPowerShell1?code=zuzIeVijuKY1nt05/wgdT1Sr3LDS9XTfYTRrbB2yf/bErY8xrT18KA=='
        powershellbase_url = self.config.get('powershell_url', powershellurl)
        cspEnabled = False
        tenantId = ""
        credsData = dict()

        companyIdKey = companyId + '_office365'
        value = self.action_service.get_value(companyIdKey, local=False)
        if value:
            credsData = json.loads(value)
        else:
            credsData['username'] = username
            credsData['password'] = password
            credsData['partnerId'] = partnerId
        credsData['cspEnabled'] = cspEnabled
        credsData['TenantId'] = tenantId

        if action.lower() == "refresh":
            if len(credsData) == 0:
                return False, "Unable to find credentials for refresh"
            credentials = azure.common.credentials.ServicePrincipalCredentials(
                client_id=str(credsData.get("graphClientId", "")),
                secret=str(credsData.get("graphClientSecret", "")),
                tenant=str(credsData.get("DefaultDomainName", "")),
                resource='https://graph.windows.net'
            )
            token_response = credentials.__dict__
            if "token" in token_response and "access_token" in token_response["token"]:
                credsData['accessToken'] = token_response['token'].get('access_token')
            self.action_service.set_value(name=companyIdKey, value=json.dumps(credsData), local=False)
        elif action.lower() == "create":
            if len(username) == "" or len(password) == "":
                print "username and password required for create action"
                return False, "username and password required for create action"
            script = '''
                    $bytes = New-Object Byte[] 32
                    $rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                    $rand.GetBytes($bytes)
                    $rand.Dispose()
                    $newClientSecret = [System.Convert]::ToBase64String($bytes)
                    '''
            if cspEnabled and tenantId:
                tennantId = " -TenantId '" + tenantId + "'"
                script += '''
                $appDetails  = New-MsolServicePrincipal -DisplayName "CloudConsoleGrapApi" -Type password -Value $newClientSecret  %s
                $appDetails | ConvertTo-Json
                $role = Get-MsolRole -RoleName "Company Administrator" %s -ErrorAction SilentlyContinue
                if($role -ne $Null){
                $role1=Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType ServicePrincipal %s -ErrorAction SilentlyContinue}
                $role2=Add-MsolRoleMember -RoleObjectId 88d8e3e3-8f55-4a1e-953a-9b9898b8876b -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType servicePrincipal %s -ErrorAction SilentlyContinue
                $role3=Add-MsolRoleMember -RoleObjectId 9360feb5-f418-4baa-8175-e2a00bac4301 -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType servicePrincipal %s -ErrorAction SilentlyContinue
                $role4=Add-MsolRoleMember -RoleObjectId fe930be7-5e62-47db-91af-98c3a49a38b1 -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType servicePrincipal %s -ErrorAction SilentlyContinue
    
                ''' % (tennantId, tennantId, tennantId, tennantId, tennantId, tennantId)
            else:
                script += '''
                $appDetails  = New-MsolServicePrincipal -DisplayName "CloudConsoleGrapApi" -Type password -Value $newClientSecret
                $appDetails | ConvertTo-Json
                $role = Get-MsolRole -RoleName "Company Administrator" -ErrorAction SilentlyContinue
                if($role -ne $Null){
                $role1=Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType ServicePrincipal -ErrorAction SilentlyContinue}
                $role2=Add-MsolRoleMember -RoleObjectId 88d8e3e3-8f55-4a1e-953a-9b9898b8876b -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType servicePrincipal -ErrorAction SilentlyContinue
                $role3=Add-MsolRoleMember -RoleObjectId 9360feb5-f418-4baa-8175-e2a00bac4301 -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType servicePrincipal -ErrorAction SilentlyContinue
                $role4=Add-MsolRoleMember -RoleObjectId fe930be7-5e62-47db-91af-98c3a49a38b1 -RoleMemberObjectId $appDetails.ObjectId -RoleMemberType servicePrincipal -ErrorAction SilentlyContinue
                '''

            queryDict = {"query1": script, "query2": "\n $newClientSecret= \"'$newClientSecret'\" \n $newClientSecret"}
            queryDict['username'] = username
            queryDict['password'] = password
            (status, resp) = self.doRequest(powershellbase_url, "POST", "", data=json.dumps(queryDict))
            if status:
                result1 = resp['result1']
                result2 = resp['result2']

                if cspEnabled and tenantId:
                    defaultDomain = tenantId
                else:
                    defaultDomain = username.split("@")[1]
                credsData['DefaultDomainName'] = defaultDomain
                credentials = azure.common.credentials.ServicePrincipalCredentials(
                    client_id=str(result1["AppPrincipalId"]),
                    secret=str(result2),
                    tenant=str(defaultDomain),
                    resource='https://graph.windows.net'
                )
                token_response = credentials.__dict__
                try:
                    if "token" in token_response and "access_token" in token_response["token"]:
                        credsData['isGraphAPIEnabled'] = True
                        credsData['accessToken'] = token_response['token'].get('access_token')
                        credsData['graphClientId'] = result1["AppPrincipalId"]
                        credsData['graphClientSecret'] = str(result2)
                    else:
                        if "error" in token_response:
                            return False, token_response["error"]
                        return False, "Not able to get accesstoken to add Office 365 credentials"

                    # Updated to datastore
                    if len(credsData):
                        self.action_service.set_value(name=companyIdKey, value=json.dumps(credsData), local=False)

                    return True, "Updated Office 365 credentials"
                except Exception, e:
                    data = e.__dict__
                    errorexception = data['inner_exception'].__dict__
                    errordata = errorexception['description'].split(':')
                    return False, errordata[1].split('Trace ID')[0]
