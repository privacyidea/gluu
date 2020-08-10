from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import AuthenticationService, SessionIdService
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import UserService
from org.gluu.util import StringHelper

# TODO: Import the privacyIDEA Java SDK

import java


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "privacyIDEA. Initialization"

        # Here we will read all necessary configuration options to initialize the privacyIDEA JAVA SDK
        if not configurationAttributes.containsKey("privacyidea_url"):
            print "privacyIDEA. Initialization. Property privacyidea_url is mandatory"
            return False
        self.privacyideal_url = configurationAttributes.get("privacyidea_url").getValue2()

        # TODO: Add further necessary parameters like:
        # * default realm
        # * SSL verification
        # * ...
        # self.privacyIDEA_Client = CreateInstanceFromSDK()

        return True   

    def destroy(self, configurationAttributes):
        print "privacyIDEA. Destroy"
        print "privacyIDEA. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        # TODO: Here we do the actual authentication.
        if step == 1:
            print "privacyIDEA. Authenticate against privacyIDEA"
            authenticationService = CdiUtil.bean(AuthenticationService)
            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()
            user_name = credentials.getUsername()
            user_password = credentials.getPassword()

            # TODO: Now call the validate/check method of the SDK and pass the user_name and user_password.

            return True
        else:
            # TODO: If we have challenge response, we probably do further steps to answer the challenges
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if step == 1:
            print "privacyIDEA. Prepare for Step 1"
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        # TODO: If we have challenge response, we need to return the templates here
        return ""

    def logout(self, configurationAttributes, requestParameters):
        return True
