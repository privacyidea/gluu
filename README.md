This is the authentication script to authenticate Gluu against privacyIDEA.

# Setup

* Download the jar-with-dependencies from [here](https://github.com/privacyidea/sdk-java/releases).
* Change the name to ``java_sdk.jar`` and put it in ``/opt/gluu-server/opt``.
* Alternatively put the file under any name anywhere in ``/opt/gluu-server/`` and configure the path later.

#### If integrated in the server, the steps below will be unneccessary:

* Put ``privacyidea.py`` somewhere and configure the path  **relative** to ``/opt/gluu-server/``, e.g. file at ``/opt/gluu-server/opt/privacyidea.py`` with configuration entry ``/opt/privacyidea.py``.
* **OR** copy-paste the contents into the script field in the configuration

* Put ``privacyidea.xhtml`` into ``/opt/gluu-server/opt/jetty-x.x/temp/jetty-localhost-8081-oxauth_war-_oxauth-any-.../webapp/auth/privacyidea/privacyidea.xhtml``.

# Configuration

* Create a new Person Authentication script, choose file and enter the path to the ``.py`` file like explained above or choose database and paste its contents.

* Add a new attribute with the key ``privacyidea_url`` and the url to the privacyIDEA Server as value.

* If the java sdk is not in the above mentioned default location, add the key ``sdk_path`` with the path to the file including its compelete name as value.

#### The following keys are optional:

* ``realm`` : specify a realm that will be appended to each request.
* ``sslverify`` : set to ``0`` to disable peer verification.
* ``log_from_sdk`` with any value: enable the logging of the jar.

* **After finishing the configuration, change the default authentication method to the Person Authentication script you just created.**

#### Logfile

* The logfile for scripts is located at ``/opt/gluu-server/opt/gluu/jetty/oxauth/logs/oxauth_script.log``.
