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
        print("privacyIDEA. URL: {0!s}".format(self.privacyideal_url))

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
        print("privacyIDEA. IsValidAuthMethod")
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        # TODO: Here we do the actual authentication.
        print("privacyIDEA. authenticating in step {0!s}.".format(step))
        if step == 1:
            print "privacyIDEA. Authenticate against privacyIDEA"
            print "privacyIDEA. exit authenticate"
            return True

            authenticationService = CdiUtil.bean(AuthenticationService)
            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()
            user_name = credentials.getUsername()
            user_password = credentials.getPassword()

            # TODO: Now call the validate/check method of the SDK and pass the user_name and user_password.

            return True
        else:
            # TODO: If we have challenge response, we probably do further steps to answer the challenges
            print("privacyIDEA. Authenticate. Further step")
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if step == 1:
            print "privacyIDEA. Prepare for Step 1"
            return True
        else:
            print("privacyIDEA. Prepare for another Step {0!s}.".format(step))
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        print("privacyIDEA. No parameter for step {0!s}.".format(step))
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        print("privacyIDEA. getCountAuthSteps. One auth steps.")
        return 1

    def getPageForStep(self, configurationAttributes, step):
        # TODO: If we have challenge response, we need to return the templates here
        print("privacyIDEA. No extra HTML page for {0!s}.".format(step))
        return ""

    def logout(self, configurationAttributes, requestParameters):
        print("privacyIDEA. No logout")
        return True
