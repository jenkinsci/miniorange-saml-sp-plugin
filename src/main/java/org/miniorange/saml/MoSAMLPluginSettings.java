package org.miniorange.saml;

import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

public class MoSAMLPluginSettings {

    private String idpEntityId;
    private String ssoUrl;
    private String publicx509Certificate;
    private String usernameCaseConversion;
    private String usernameAttribute;
    private String emailAttribute;
    private String nameIDFormat;
    private String loginType;
    private String regexPattern;
    private Boolean enableRegexPattern;
    private Boolean signedRequest;
    private Boolean userCreate;
    private Boolean forceAuthn;
    private String  ssoBindingType;
    private List<MoAttributeEntry> samlCustomAttributes;
    private String authnContextClass;

    //    //crowd groups fetch
        private String crowdURL;
        private String crowdApplicationName;
        private Secret crowdApplicationPassword;

    private static final String PRIVATE_CERT_PATH = "/certificates/sp-key.key";
    private static final String PUBLIC_CERT_PATH = "/certificates/sp-certificate.crt";
    private static  String PRIVATE_CERTIFICATE = "";
    private static  String PUBLIC_CERTIFICATE = "";
    private static final Logger LOGGER = Logger.getLogger(MoSAMLManager.class.getName());

    static {
        try {

            PRIVATE_CERTIFICATE = IOUtils.toString(MoSAMLPluginSettings.class.getResourceAsStream(PRIVATE_CERT_PATH),
                    "UTF-8");
            PRIVATE_CERTIFICATE = MoSAMLUtils.serializePrivateCertificate(PRIVATE_CERTIFICATE);

            PUBLIC_CERTIFICATE = IOUtils.toString(MoSAMLPluginSettings.class.getResourceAsStream(PUBLIC_CERT_PATH),
                    "UTF-8");
            PUBLIC_CERTIFICATE = MoSAMLUtils.serializePublicCertificate(PUBLIC_CERTIFICATE);


        } catch (IOException e) {
            LOGGER.fine("An I/O error occurred while initializing the SAML Settings.");
        }
    }
        public MoSAMLPluginSettings (String idpEntityId, String ssoUrl,
                                 String publicx509Certificate, String usernameCaseConversion,
                                 String usernameAttribute, String emailAttribute,
                                 String nameIDFormat, String loginType,
                                 String regexPattern, Boolean enableRegexPattern, Boolean signedRequest,
                                 Boolean userCreate , Boolean forceAuthn, String ssoBindingType, List<MoAttributeEntry> samlCustomAttributes, String authnContextClass, String crowdURL,
                                 String crowdApplicationName, Secret crowdApplicationPassword) {
        this.idpEntityId = idpEntityId;
        this.ssoUrl = ssoUrl;
        this.publicx509Certificate = publicx509Certificate;
        this.usernameCaseConversion = (usernameCaseConversion != null) ? usernameCaseConversion : "none";
        this.usernameAttribute = (usernameAttribute != null && !usernameAttribute.trim().equals("")) ? usernameAttribute : "NameID";
        this.emailAttribute = (emailAttribute != null && !emailAttribute.trim().equals("")) ? emailAttribute : "NameID";
        this.nameIDFormat= (nameIDFormat != null) ? nameIDFormat : "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        this.loginType = (loginType != null) ? loginType : "usernameLogin";
        this.regexPattern= regexPattern;
        this.enableRegexPattern= (enableRegexPattern != null) ? enableRegexPattern : false;;
        this.signedRequest= (signedRequest != null) ? signedRequest : false;
        this.userCreate = (userCreate != null) ? userCreate : false;
        this.forceAuthn = (forceAuthn != null) ? forceAuthn : false;
        this.ssoBindingType = (ssoBindingType != null) ? ssoBindingType : "HttpRedirect";
        this.samlCustomAttributes = samlCustomAttributes;
        this.authnContextClass= (authnContextClass != null) ? authnContextClass : "None";
        this.crowdURL=crowdURL;
        this.crowdApplicationName=crowdApplicationName;
        this.crowdApplicationPassword=crowdApplicationPassword;
    }


    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSsoUrl() { return ssoUrl; }

    public String getPublicx509Certificate() {
        return publicx509Certificate;
    }

    public String getUsernameCaseConversion() {
        return usernameCaseConversion;
    }

    public String getUsernameAttribute() {
        return usernameAttribute;
    }

    public String getEmailAttribute() {
        return emailAttribute;
    }

    public String getSPBaseUrl() {
        String rootURL= Jenkins.get().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getSPEntityID() {
        String rootURL= Jenkins.get().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getSPAudienceURI() {
        String rootURL= Jenkins.get().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getSpAcsUrl() {
        return getSPBaseUrl() + "/securityRealm/moSamlAuth";
    }

    public String getPrivateSPCertificate() { return MoSAMLUtils.serializePrivateCertificate(PRIVATE_CERTIFICATE); }

    public String getNameIDFormat() { return nameIDFormat; }

    public boolean getSignedRequest() {
        return signedRequest;
    }

    public String getLoginType() { return loginType; }

    public String getRegexPattern() {
        return regexPattern;
    }

    public Boolean getEnableRegexPattern() { return enableRegexPattern; }

    public String getOrganizationName() { return "Xecurify"; }

    public String getOrganizationDisplayName() { return "Xecurify"; }

    public String getOrganizationUrl() { return "http://miniorange.com"; }

    public String getTechnicalContactName() { return "Xecurify"; }

    public String getTechnicalContactEmail() { return "info@xecurify.com"; }

    public String getSupportContactName() { return "Xecurify"; }

    public String getSupportContactEmail() { return "info@xecurify.com"; }

    public Boolean getUserCreate() { return userCreate; }

    public Boolean getForceAuthn() { return forceAuthn; }

    public String getPublicSPCertificate(){ return MoSAMLUtils.serializePublicCertificate(PUBLIC_CERTIFICATE); }

    public String getSsoBindingType() { return ssoBindingType; }

    public String getspSLOURL() {
        return getSPBaseUrl() + "/securityRealm/logout";
    }

    public List<MoAttributeEntry> getSamlCustomAttributes() {
        LOGGER.fine("Updating Custom Attributes.");
        if (samlCustomAttributes == null) {
            return java.util.Collections.emptyList();
        }
        return samlCustomAttributes; }

    public String getAuthnContextClass() {
        return authnContextClass;
    }

    public String getCrowdURL() {
        return crowdURL;
    }

    public String getCrowdApplicationName() {
        return crowdApplicationName;
    }

    public Secret getCrowdApplicationPassword() {
        return crowdApplicationPassword;
    }
}
