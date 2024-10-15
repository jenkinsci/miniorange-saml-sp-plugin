# SAML Single Sign On (SSO) for Jenkins

![image_1](docs/images/jenkins-sso.png)

⭐  **Click [here](https://miniorange.atlassian.net/wiki/spaces/JEN/pages/2962554886/Jenkins+Saml+SSO+Premium+Trial+Activation) to try out the premium plugin for free** ⭐

**SAML Single Sign On (SSO) for Jenkins** plugin allows SSO with ADFS, Azure AD, Azure AD B2C, Keycloak, Okta,
Shibboleth, Salesforce, GSuite / Google Apps, AWS, Office 365, SimpleSAMLphp, OpenAM, Centrify, Ping, RSA, IBM, Oracle,
OneLogin, Bitium, WSO2, Auth0, AuthAnvil and all SAML 2.0 capable Identity Providers to securely authenticate the users
into Jenkins.

**Features of Jenkins Saml SP Plugin**

* Simple and easy-to-use [ FREE ]
* Supports both SSO and Jenkins’ own login at the same time [FREE]
* Auto Create Users[FREE]
* Encrypted SSO requests and response [FREE]
* Support to the Proxy Setup [FREE]
* Export SAML configurations. [FREE]
* Attribute Mapping [PREMIUM]
* Auto-redirect to IdP [PREMIUM]
* Custom Attribute Mapping [PREMIUM]
* Just In Time Group/Role Provisioning [PREMIUM]
* Supports all the authorization strategies for role/group mapping [PREMIUM]
* Manual Group/Role Mapping [PREMIUM]
* 24*7 support [PREMIUM]
* Back-door Login [PREMIUM]
* Single Logout [PREMIUM]

Facing issue with SSO? Refer below steps to generate error Logs and send it to info@xecurify.com. We will help you
resolve your issue in no time.

⭐  **Looking to connect Crowd to your Jenkins and manage users and groups from crowd seamlessly? Try our [Crowd Connector Plugin](https://www.miniorange.com/atlassian/jenkins-crowd-sso-connector#free-plugin) today!** ⭐

⭐ **Secure your Jenkins environment with two-factor authentication with our 2FA Plugin. Try our [Jenkins 2FA Pluing](https://miniorange.atlassian.net/wiki/spaces/JEN/pages/2969239626/Jenkins+2FA+Premium+Trial+Activation+Guide) today.** ⭐

### **[Frequently Asked Questions](https://faq.miniorange.com/kb/jenkins/)**

Looking for **Two Factor Authentication(2FA)/OAuth Single Sign On (SSO)** for Jenkins ? Contact us at info@xecurify.com
for more details.

Supported IDP’s:

If you require Jenkins SAML Single Sign On (SSO) application or need any help with installing this plugin, please feel
free to email us at info@xecurify.com.

LIST OF SUPPORTED IDPS:

* [Azure AD](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-azure-ad-as-idp/) (supports SAML
  SSO for Jenkins login)
* [Keycloak](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-jboss-keycloak-as-idp/) (supports
  SAML SSO for Jenkins login)
* [ADFS](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-adfs-as-idp/) (supports SAML SSO for
  Jenkins login)
* [Okta](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-okta-as-idp) (supports SAML SSO for
  Jenkins login)
* [Salesforce](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-salesforce/) (supports SAML SSO
  for Jenkins login)
* [Shibboleth 2](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-shibboleth2/) (supports SAML
  SSO for Jenkins login)
* [GSuite / Google Apps](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-google-apps-g-suite-as-idp/) (
  supports SAML SSO for Jenkins login)
* [miniOrange](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-miniorange-as-idp/) (supports
  SAML SSO for Jenkins login)
* [OneLogin](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-onelogin-as-idp/) (supports SAML
  SSO for Jenkins login)
* [Centrify](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-centrify-as-idp/) (supports SAML
  SSO for Jenkins login)
* [SimpleSAML](https://www.miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-simplesaml) (supports SAML
  SSO for Jenkins login)
* [OpenAM](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-openam-as-idp/) (supports SAML SSO
  for Jenkins login)
* [PingOne](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-ping-one/) (supports SAML SSO for
  Jenkins login)
* [RSA](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-rsa-securid/) (supports SAML SSO for
  Jenkins login)
* [Oracle](https://www.miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-oracle-enterprise-manager) (
  supports SAML SSO for Jenkins login)
* [Bitium](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-bitium-as-idp/) (supports SAML SSO
  for Jenkins login)
* [WSO2](https://www.miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-wso2) (supports SAML SSO for Jenkins
  login)
* [Auth0](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-auth0-as-idp/) (supports SAML SSO for
  Jenkins login)
* [AuthAnvil](https://miniorange.com/atlassian/saml-single-sign-on-sso-into-jenkins-using-authanvil-as-idp/) (supports SAML
  SSO for Jenkins login)

  and practically any SAML compliant Identity Provider.

In addition to the above, [miniOrange](/docs/images/miniorange_as_idp.md) also provides On-Premise IDP.

SAML Single Sign-on (SSO) acts as a SAML 2.0 Service Provider and securely authenticates users with your SAML 2.0
Identity Provider.

## On Jenkins side:

**Step 1: Download and install the plugin in Jenkins.**

To download the miniorange saml SP plugin follow the path:
**Through Jenkins plugin directory**

* Login to your Jenkins.
* Go to **Manage Jenkins** option from the left pane, and open **Manage Plugins** tab.

![image_1](docs/images/configuration/manage_plugin.png)

* Search for ‘**Miniorange**’ in the available tab.
  ![image_2](docs/images/configuration/available-tab-install.png)
* Download and install with a restart.

![image_3](docs/images/configuration/plugin_installed_2.png)

Or
**Manual Configuration:**

* Login to your Jenkins.
* Go to **Manage Jenkins** option from the left pane, and open **Manage Plugins** tab.
* Go to the **advanced** tab and upload the hpi file.
* You can get the hpi file by running ```mvn clean package``` command on this code. Contact info@xecurify.com if you are
  facing any issue.

![image_4](docs/images/configuration/upload_plugin.png)

![image_5](docs/images/configuration/plugin_installed_2.png)

**Step 2: To activate the plugin**

* Open **Manage Jenkins** => **Configure Global Security** and set the **Security Realm** as **miniorange SAML 2.0**.

![image_6](docs/images/configuration/configure_global_sec.png)

![image_7](docs/images/configuration/set_security_realm.png)

* Again go to **Manage Jenkins** => **miniOrange SAML SSO**.
  ![image_8](docs/images/configuration/configure_SAML_plugin.png)

**Step:3:** Configure you Idp using SP configuration.
![image_9](docs/images/configuration/SP_configuration.png)

* After configuring your Idp, Set up Jenkins as a service provider by any of the three options:
* Enter the metadata URL and save the settings.
  ![image_10](docs/images/configuration/metadataUrl.png)
* Enter the metadata file path and save the settings.
  ![image_10](docs/images/configuration/metadataFilePath.png)
* Manually enter the Idp side values and save the settings.
  ![image_10](docs/images/configuration/manual_Idp_configuration.png)
