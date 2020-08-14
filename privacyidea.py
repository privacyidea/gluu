from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import AuthenticationService, SessionIdService
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil



# TODO: Import the privacyIDEA Java SDK

import java


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.identity = CdiUtil.bean(Identity)
        self.sessionIdService = CdiUtil.bean(SessionIdService)
        self.authenticationService = CdiUtil.bean(AuthenticationService)

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
        print("privacyIDEA. AUTH STEP {0!s}.".format(step))
        if step == 1:
            print "privacyIDEA. Authenticate against privacyIDEA"
            credentials = self.identity.getCredentials()
            user_name = credentials.getUsername()
            user_password = credentials.getPassword()

            # TODO: Run /validate/check for the first time with user_name and user_password
            if user_password == "pin":
                print("privacyIDEA. The first auth step was successful")
                # If the user is successfully authenticated, we need to add "aut_user" to the session.
                sessionId = self.sessionIdService.getSessionId() # fetch from persistence
                sessionId.getSessionAttributes().put("pi_transaction_id", "blabla")
                self.sessionIdService.updateSessionId(sessionId)
                print("privacyIDEA. Updating pi_transaction_id")
                self.authenticationService.authenticate(user_name)

                print("privacyIDEA. Authenticate. Logged in: {0!s}".format(user_name))
                # We have to return True to get to the next step!
                return True

        elif step == 2:
            # TODO: Run /validate/check a second time and respond the challenge
            print("privacyIDEA. Challenge Response")
            credentials = self.identity.getCredentials()
            #user_name = credentials.getUsername()
            sessionId = self.sessionIdService.getSessionId()
            user_name = sessionId.getSessionAttributes().get("auth_user")
            user_password = credentials.getPassword()
            print("privacyIDEA. Authenticate. CHALLENGE RESPONSE!")
            print("privacyIDEA. {0!s} / {1!s}.".format(user_name, user_password))
            # TODO: Send the password and the transaction_id to privacyIDEA.
            # Pass the user into the session.
            if user_password == "otp":
                return True

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if step == 1:
            print "privacyIDEA. Prepare for Step 1"
            return True
        elif step == 2:
            # This is a 2nd challenge response step
            print("privacyIDEA. Prepare for another Step {0!s}.".format(step))
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        print("privacyIDEA. No parameter for step {0!s}.".format(step))
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        # TODO: We need to be able to return dynamic number of steps.
        #       At the beginnding of the authentication process we do not
        #       know how many steps it will take.
        print("privacyIDEA. getCountAuthSteps.")
        sessionId = self.sessionIdService.getSessionId()
        transaction_id = sessionId.getSessionAttributes().get("pi_transaction_id")
        if transaction_id:
            print("privacyIDEA. getCountAuthSteps. Challenge Response.")
            return 2
        else:
            print("privacyIDEA. getCountAuthSteps. One auth steps.")
            return 1

    def getPageForStep(self, configurationAttributes, step):
        if step == 1:
            print("privacyIDEA. No extra HTML page for {0!s}.".format(step))
        elif step == 2:
            # TODO: further authentication steps need to use our own login form, that handles the response
            #       to the challenge. Currently it is not clear to me, how the templates are found.
            # See             return "/auth/otp_sms/otp_sms.xhtml"
            return ""
            #return "/auth/privacyidea/challenge-response.xhtml"
        return ""

    def logout(self, configurationAttributes, requestParameters):
        print("privacyIDEA. No logout")
        return True
