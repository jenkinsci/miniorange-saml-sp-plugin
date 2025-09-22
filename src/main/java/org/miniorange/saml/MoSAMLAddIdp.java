package org.miniorange.saml;

import hudson.util.Secret;
import net.sf.json.JSONArray;
import org.apache.commons.io.FileUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.kohsuke.stapler.verb.POST;
import org.miniorange.saml.testConfiguration.TestConfigurationFailed;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.BooleanUtils;

import org.json.JSONException;
import org.json.JSONObject;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.apache.commons.io.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;


import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import hudson.tasks.Mailer;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.impl.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import static jenkins.model.Jenkins.get;
import static org.miniorange.saml.MoHttpUtils.sendGetRequest;

public class MoSAMLAddIdp extends SecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(MoSAMLAddIdp.class.getName());
    public static final String MO_SAML_SP_AUTH_URL = "securityRealm/moSamlAuth";
    public static final String MO_JENKINS_LOGIN_ACTION = "securityRealm/moLoginAction";
    public static final String MO_JENKINS_SAML_LOGIN_ACTION = "securityRealm/moSamlLogin";
    public static final String MO_SAML_SSO_FORCE_STOP = "securityRealm/moSAMLSingleSignOnForceStop";
    private static final String LOGIN_TEMPLATE_PATH = "/templates/mosaml_login_page_template.html";
    private static final String REFERER_ATTRIBUTE = MoSAMLAddIdp.class.getName() + ".referer";



    private final String idpEntityId;
    private final String ssoUrl;
    private final String metadataUrl;
    private final String metadataFilePath;
    private final String publicx509Certificate;
    private final String usernameAttribute;
    private final String fullnameAttribute;
    private final String usernameCaseConversion;
    private final Boolean userAttributeUpdate;
    private final String emailAttribute;
    private final String nameIDFormat;
    private final String sslUrl;
    private final String loginType;
    private final String regexPattern;
    private final Boolean enableRegexPattern;
    private final Boolean signedRequest;
    private final Boolean splitnameAttribute;
    private final Boolean userCreate;
    private final Boolean forceAuthn;
    private final String ssoBindingType;
    private final String sloBindingType;
    private List<MoAttributeEntry> samlCustomAttributes;
    private String newUserGroup;
    private String authnContextClass;
    private static Set<String> nonceSet = new HashSet<>();

    private transient TestConfigurationFailed tcf;

    //crowd groups fetch
    private String crowdURL;
    private String crowdApplicationName;
    private Secret crowdApplicationPassword;


    @DataBoundConstructor
    public MoSAMLAddIdp(String idpEntityId,
                        String ssoUrl,
                        String metadataUrl,
                        String metadataFilePath,
                        String publicx509Certificate,
                        String usernameCaseConversion,
                        String usernameAttribute,
                        String emailAttribute,
                        String fullnameAttribute,
                        String nameIDFormat,
                        String sslUrl,
                        String loginType,
                        String regexPattern,
                        Boolean enableRegexPattern,
                        Boolean signedRequest,
                        Boolean splitnameAttribute,
                        Boolean userCreate,
                        Boolean forceAuthn,
                        String ssoBindingType,
                        String sloBindingType,
                        List<MoAttributeEntry> samlCustomAttributes,
                        Boolean userAttributeUpdate,
                        String authnContextClass,
                        String crowdURL,
                        String crowdApplicationName,
                        Secret crowdApplicationPassword

    ) throws Exception {
        super();
        this.metadataUrl = metadataUrl;
        this.metadataFilePath = metadataFilePath;
        if (!StringUtils.isEmpty(metadataUrl) || !StringUtils.isEmpty(metadataFilePath) ) {
            String metadata = (!StringUtils.isEmpty(metadataUrl) ? sendGetRequest(metadataUrl, null) : getMetadataFromFile(metadataFilePath));
            List<String> metadataUrlValues = configureFromMetadata(metadata);
            if (metadataUrlValues.size() != 0) {

                this.idpEntityId = metadataUrlValues.get(0);
                this.nameIDFormat = metadataUrlValues.get(1);
                this.ssoUrl = metadataUrlValues.get(2);
                this.sslUrl = "";
                this.publicx509Certificate = metadataUrlValues.get(4);
            }
            else {
                this.idpEntityId = idpEntityId;
                this.ssoUrl = ssoUrl;
                this.nameIDFormat = nameIDFormat;
                this.sslUrl = sslUrl;
                this.publicx509Certificate = publicx509Certificate;
            }

        }
        else{
            this.idpEntityId = idpEntityId;
            this.ssoUrl = ssoUrl;
            this.nameIDFormat = nameIDFormat;
            this.sslUrl = sslUrl;
            this.publicx509Certificate = publicx509Certificate;
        }

        this.usernameCaseConversion = (usernameCaseConversion != null) ? usernameCaseConversion : "none";
        this.usernameAttribute = (usernameAttribute != null && !usernameAttribute.trim().equals("")) ? usernameAttribute : "NameID";
        this.emailAttribute = (emailAttribute != null && !emailAttribute.trim().equals("")) ? emailAttribute : "NameID";
        this.loginType = (loginType != null) ? loginType : "usernameLogin";
        this.regexPattern = regexPattern;
        this.enableRegexPattern = (enableRegexPattern != null) ? enableRegexPattern : false;
        this.signedRequest = (signedRequest != null) ? signedRequest : false;
        this.splitnameAttribute = (splitnameAttribute != null) ? splitnameAttribute : false;
        this.userCreate = (userCreate != null) ? userCreate : true;
        this.forceAuthn = (forceAuthn != null) ? forceAuthn : false;
        this.ssoBindingType = (ssoBindingType != null) ? ssoBindingType : "HttpRedirect";
        this.sloBindingType =  (sloBindingType != null) ? sloBindingType : "HttpRedirect";
        this.samlCustomAttributes = samlCustomAttributes;
        this.userAttributeUpdate = (userAttributeUpdate != null) ? userAttributeUpdate : false;
        this.fullnameAttribute = fullnameAttribute;
        this.authnContextClass=(authnContextClass != null) ? authnContextClass : "None";
        this.crowdURL=crowdURL;
        this.crowdApplicationName=crowdApplicationName;
        this.crowdApplicationPassword=crowdApplicationPassword;
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/moLogin";
    }

    @Override
    public void doLogout(StaplerRequest req, StaplerResponse rsp) {
        try {
            LOGGER.fine(" in doLogout");
            super.doLogout(req, rsp);
        } catch (Exception e) {
            LOGGER.fine("error Occurred while generating logout request " + e.getMessage());
        }

    }

    @Override
    public String getPostLogOutUrl2(StaplerRequest req, Authentication auth) {
        return req.getContextPath() + "/securityRealm/moLogin?from=" + req.getContextPath();
    }

    public HttpResponse doMoLogin(final StaplerRequest request, final StaplerResponse response, String errorMessage) {
        String referer= request.getReferer();
        String redirectOnFinish = calculateSafeRedirect(referer);
        request.getSession().setAttribute(REFERER_ATTRIBUTE, redirectOnFinish);
        return (req, rsp, node) -> {
            rsp.setContentType("text/html;charset=UTF-8");
            String html = IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");
            String baseURL=get().getRootUrl();
            if(baseURL.endsWith("/")){
                baseURL= baseURL.substring(0,baseURL.length()-1);
            }
            html = html.replace("$$resURL$$",baseURL);
            if (StringUtils.isNotBlank(errorMessage)) {
                html = html.replace("<input type=\"hidden\" />", errorMessage);
            }
            rsp.getWriter().println(html);
        };
    }

    @RequirePOST
    @SuppressWarnings("unused")
    public void doMoLoginAction(final StaplerRequest request, final StaplerResponse response) {
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        String redirectOnFinish = calculateSafeRedirect(referer);
        recreateSession(request);
        try {
            {
                String username = request.getParameter("j_username");
                username = MoSAMLUtils.sanitizeText(username);
                String password = request.getParameter("j_password");
                password = MoSAMLUtils.sanitizeText(password);
                Boolean isValidUser= Boolean.FALSE ;
                String error = StringUtils.EMPTY;
                if (StringUtils.isNotBlank(username)) {
                    final User user_jenkin = User.getById(username, false);
                    if (user_jenkin != null) {
                        LOGGER.fine("User exist with username = " + username);
                        try {
                            HudsonPrivateSecurityRealm.Details details=user_jenkin.getProperty(HudsonPrivateSecurityRealm.Details.class);
                            isValidUser= details.isPasswordCorrect(password);
                            LOGGER.fine("Valid User Password");
                        } catch (Exception e) {
                            LOGGER.fine("InValid User Password"+e.getMessage());
                            isValidUser = Boolean.FALSE;
                        }
                        if (isValidUser) {
                            HttpSession session = request.getSession(false);
                            if (session != null) {
                                session.invalidate();
                            }
                            request.getSession(true);
                            MoSAMLUserInfo userInfo = new MoSAMLUserInfo(username, Collections.singleton(AUTHENTICATED_AUTHORITY2));
                            MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
                            SecurityContextHolder.getContext().setAuthentication(tokenInfo);
                            SecurityListener.fireAuthenticated2(userInfo);
                            SecurityListener.fireLoggedIn(user_jenkin.getId());
                            response.sendRedirect(redirectOnFinish);
                            return;
                        }
                    }
                    error = "INVALID USER OR PASSWORD";
                }
                String errorMessage = StringUtils.EMPTY;
                if (StringUtils.isNotBlank(error)) {
                    errorMessage = "<div class=\"alert alert-danger\">Invalid username or password</div><br>";
                }
                String html = customLoginTemplate(response, errorMessage);
                response.getWriter().println(html);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String calculateSafeRedirect(String referer) {
        String redirectURL;
        String rootUrl = getBaseUrl();
        {
            if (referer != null && (referer.startsWith(rootUrl) || Util.isSafeToRedirectTo(referer))) {
                redirectURL = referer;
            } else {
                redirectURL = rootUrl;
            }
        }
        LOGGER.fine("Safe URL redirection: " + redirectURL);
        return redirectURL;
    }

    private String customLoginTemplate(StaplerResponse response, String errorMessage) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String html = IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");
        String baseURL=get().getRootUrl();
        if(baseURL.endsWith("/")){
            baseURL= baseURL.substring(0,baseURL.length()-1);
        }
        html = html.replace("$$resURL$$",baseURL);
        if (StringUtils.isNotBlank(errorMessage)) {
            LOGGER.fine(errorMessage);

            html = html.replace("<input type=\"hidden\" />", errorMessage);

        }
        return html;
    }

    private String createNonce() {
        UUID uuid = UUID.randomUUID();
        String uuidAsString = uuid.toString();
        return uuidAsString;
    }

    @SuppressWarnings("unused")
    public void doMoSamlLogin(final StaplerRequest request, final StaplerResponse response, @Header("Referer") final String referer) {
        recreateSession(request);

        String redirectOnFinish = StringUtils.EMPTY;
        if(StringUtils.isEmpty(request.getQueryString())){
            redirectOnFinish = calculateSafeRedirect(referer);
        }
        else{
            redirectOnFinish = request.getQueryString();
        }
        HttpSession session = request.getSession();


        LOGGER.fine("relay state " + redirectOnFinish);

        String base64Nonce = createNonce();
        nonceSet.add(base64Nonce);
        String redirectUrl = calculateSafeRedirect(redirectOnFinish);
        String fromParam = StringUtils.substringAfter(redirectUrl, "from=");
        String flowType = StringUtils.equals(fromParam, "testidpconfiguration") ? "testidpconfiguration" : StringUtils.EMPTY;
        String relayState = StringUtils.join(new String[] {base64Nonce, flowType}, '|');

        LOGGER.fine("in doMoSamlLogin");
        MoSAMLManager moSAMLManager = new MoSAMLManager();
        moSAMLManager.createAuthnRequestAndRedirect(request, response, relayState, getMoSAMLPluginSettings());
    }

    public String getBaseUrl() {
        return get().getRootUrl();
    }

    @RequirePOST
    @SuppressWarnings("unused")
    public void doMoSAMLSingleSignOnForceStop(final StaplerRequest request, final StaplerResponse response) {
        HttpSession session= request.getSession(false);
        if(session!=null){
            session.invalidate();
        }
        LOGGER.fine("Enable doMoSAMLSingleSignOnForceStop from doPost");
        String username = request.getParameter("username");
        username = MoSAMLUtils.sanitizeText(username);
        String password = request.getParameter("password");
        password = MoSAMLUtils.sanitizeText(password);
        LOGGER.fine("Parameters submitted for backdoor: username: "+username+" Password: "+password);
        if (StringUtils.isBlank(username) && StringUtils.isBlank(password)) {
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Authorization parameters are Missing");
            return;
        }
        final User user_jenkin = User.getById(username, false);
        try {
            if (user_jenkin != null ) {
                HudsonPrivateSecurityRealm.Details details=user_jenkin.getProperty(HudsonPrivateSecurityRealm.Details.class);
                Boolean  isValidUser= details.isPasswordCorrect(password);
                Jenkins j= Jenkins.getInstanceOrNull();
                if (j!=null&& isValidUser)
                    j.setSecurityRealm(new HudsonPrivateSecurityRealm(false, false, null));
                JSONObject json = new JSONObject();
                JSONObject success = new JSONObject();
                success.put("Status", "SUCCESS");
                success.put("Message", "Successfully disabled SSO");
                json.put("Message", success);
                response.setContentType("application/json");
                response.setStatus(200);
                response.getOutputStream().write(json.toString().getBytes(StandardCharsets.UTF_8));
                response.getOutputStream().close();
            }
            else{
                LOGGER.fine("User validation failed.");
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorize User");
            }
        }
           catch (IOException e)
           {
               LOGGER.fine(e.getMessage());
           }
    }

    private void sendError(StaplerResponse response, int errorCode, String errorMessage) {
        try {
            JSONObject json = new JSONObject();
            JSONObject error = new JSONObject();
            error.put("Status", "ERROR");
            error.put("Message", errorMessage);
            json.put("error", error);
            response.setContentType("application/json");
            response.setStatus(errorCode);
            response.getOutputStream().write(json.toString().getBytes(StandardCharsets.UTF_8));
            response.getOutputStream().close();
        } catch (JSONException | IOException e) {
            LOGGER.fine("An error occurred while sending json response" + e);
        }
    }

    @SuppressWarnings("unused")
    public void doMospmetadata(final StaplerRequest request, final StaplerResponse response) {
        LOGGER.fine("Printing SP Metadata");
        HttpSession session=request.getSession(false);
        if(session!=null){
            MoSAMLPluginSettings moSAMLPluginSettings = getMoSAMLPluginSettings();
            String metadata = getMetadata(moSAMLPluginSettings);
            LOGGER.fine(metadata);
            try {
                response.setHeader("Content-Disposition", "attachment; filename=\"sp_metadata.xml\"");
                response.setHeader("Cache-Control", "max-age=0");
                response.setHeader("Pragma", "");
                response.setContentType("application/xml");
                response.getOutputStream().write(metadata.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                LOGGER.fine("An error occurred while downloading the metadata." + e);
            }
        }
    else{
            LOGGER.fine("Invalid Request");
            return;
        }
    }
    @SuppressWarnings("unused")
    public  void doDownloadCertificate(final StaplerRequest request, final StaplerResponse response){
        LOGGER.fine("Downloading SP Certificate.");
        try {
            MoSAMLPluginSettings moSAMLPluginSettings = getMoSAMLPluginSettings();
            String certificate = moSAMLPluginSettings.getPublicSPCertificate();
            response.setHeader("Content-Disposition", "attachment; filename=\"sp-certificate.crt\"");
            response.setHeader("Cache-Control", "max-age=0");
            response.setHeader("Pragma", "");
            response.setContentType("application/octet-stream");
            response.getOutputStream().write(certificate.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            LOGGER.fine("An error occurred while downloading the certificate."+e);
        }

    }

    public String getMetadata(MoSAMLPluginSettings settings) {
        LOGGER.fine("Generating SP Metadata.");
        MoSAMLUtils.doBootstrap();
        EntityDescriptorBuilder builder = new EntityDescriptorBuilder();
        SPSSODescriptorBuilder spssoDescriptorBuilder = new SPSSODescriptorBuilder();
        KeyDescriptorBuilder keyDescriptorBuilder = new KeyDescriptorBuilder();
        KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
        X509DataBuilder x509DataBuilder = new X509DataBuilder();
        X509CertificateBuilder x509CertificateBuilder = new X509CertificateBuilder();
        NameIDFormatBuilder nameIdFormatBuilder = new NameIDFormatBuilder();
        AssertionConsumerServiceBuilder assertionConsumerServiceBuilder = new AssertionConsumerServiceBuilder();
        SingleLogoutServiceBuilder singleLogOutServiceBuilder = new SingleLogoutServiceBuilder();
        OrganizationBuilder organizationBuilder = new OrganizationBuilder();
        OrganizationNameBuilder organizationNameBuilder = new OrganizationNameBuilder();
        OrganizationDisplayNameBuilder organizationDisplayNameBuilder = new OrganizationDisplayNameBuilder();
        OrganizationURLBuilder organizationUrlBuilder = new OrganizationURLBuilder();
        ContactPersonBuilder contactPersonBuilder = new ContactPersonBuilder();
        GivenNameBuilder givenNameBuilder = new GivenNameBuilder();
        EmailAddressBuilder emailAddressBuilder = new EmailAddressBuilder();

        EntityDescriptor entityDescriptor = builder.buildObject();
        SPSSODescriptor spssoDescriptor = spssoDescriptorBuilder.buildObject();
        AssertionConsumerService assertionConsumerService = assertionConsumerServiceBuilder.buildObject();
        Organization organization = organizationBuilder.buildObject();
        ContactPerson contactPersonTechnical = contactPersonBuilder.buildObject();
        ContactPerson contactPersonSupport = contactPersonBuilder.buildObject();

        entityDescriptor.setEntityID(settings.getSPEntityID());

        spssoDescriptor.setWantAssertionsSigned(true);
        spssoDescriptor.addSupportedProtocol("urn:oasis:names:tc:SAML:2.0:protocol");

        //signing
        if (BooleanUtils.toBoolean(settings.getSignedRequest())) {
            spssoDescriptor.setAuthnRequestsSigned(true);
            KeyDescriptor signingKeyDescriptor = keyDescriptorBuilder.buildObject();
            signingKeyDescriptor.setUse(UsageType.SIGNING);
            KeyInfo signingKeyInfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data signingX509Data = x509DataBuilder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
            X509Certificate signingX509Certificate = x509CertificateBuilder
                    .buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
            String certificate = settings.getPublicSPCertificate();
            certificate = MoSAMLUtils.deserializePublicCertificate(certificate);
            signingX509Certificate.setValue(certificate);
            signingX509Data.getX509Certificates().add(signingX509Certificate);
            signingKeyInfo.getX509Datas().add(signingX509Data);
            signingKeyDescriptor.setKeyInfo(signingKeyInfo);
            spssoDescriptor.getKeyDescriptors().add(signingKeyDescriptor);
        }

        SingleLogoutService singleLogoutServiceRedir = singleLogOutServiceBuilder.buildObject();
        singleLogoutServiceRedir
                .setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        singleLogoutServiceRedir.setLocation(settings.getspSLOURL());
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutServiceRedir);

        SingleLogoutService singleLogoutServicePost = singleLogOutServiceBuilder.buildObject();
        singleLogoutServicePost.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        singleLogoutServicePost.setLocation(settings.getspSLOURL());
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutServicePost);

        List<String> nameIds = new ArrayList<>();
        nameIds.add("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        nameIds.add("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        nameIds.add("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIds.add("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

        for (String nameId : nameIds) {
            NameIDFormat nameIDFormat = nameIdFormatBuilder.buildObject();
            nameIDFormat.setFormat(nameId);
            spssoDescriptor.getNameIDFormats().add(nameIDFormat);
        }

        assertionConsumerService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assertionConsumerService.setLocation(settings.getSpAcsUrl());
        assertionConsumerService.setIndex(1);
        spssoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        entityDescriptor.getRoleDescriptors().add(spssoDescriptor);

        OrganizationName organizationName = organizationNameBuilder.buildObject();
        organizationName.setName(new LocalizedString(settings.getOrganizationName(), Locale.getDefault().getLanguage()));
        organization.getOrganizationNames().add(organizationName);
        OrganizationDisplayName organizationDisplayName = organizationDisplayNameBuilder.buildObject();
        organizationDisplayName.setName(new LocalizedString(settings.getOrganizationDisplayName(), Locale.getDefault().getLanguage()));
        organization.getDisplayNames().add(organizationDisplayName);
        OrganizationURL organizationURL = organizationUrlBuilder.buildObject();
        organizationURL.setURL(new LocalizedString(settings.getOrganizationUrl(), Locale.getDefault().getLanguage()));
        organization.getURLs().add(organizationURL);
        entityDescriptor.setOrganization(organization);

        contactPersonTechnical.setType(ContactPersonTypeEnumeration.TECHNICAL);
        GivenName givenNameTechnical = givenNameBuilder.buildObject();
        givenNameTechnical.setName(settings.getTechnicalContactName());
        contactPersonTechnical.setGivenName(givenNameTechnical);
        EmailAddress emailAddressTechnical = emailAddressBuilder.buildObject();
        emailAddressTechnical.setAddress(settings.getTechnicalContactEmail());
        contactPersonTechnical.getEmailAddresses().add(emailAddressTechnical);

        contactPersonSupport.setType(ContactPersonTypeEnumeration.SUPPORT);
        GivenName givenNameSupport = givenNameBuilder.buildObject();
        givenNameSupport.setName(settings.getSupportContactName());
        contactPersonSupport.setGivenName(givenNameSupport);
        EmailAddress emailAddressSupport = emailAddressBuilder.buildObject();
        emailAddressSupport.setAddress(settings.getSupportContactEmail());
        contactPersonSupport.getEmailAddresses().add(emailAddressSupport);

        entityDescriptor.getContactPersons().add(contactPersonTechnical);
        entityDescriptor.getContactPersons().add(contactPersonSupport);

        try {
            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(entityDescriptor);
            Element element = marshaller.marshall(entityDescriptor);
            return XMLHelper.nodeToString(element);
        } catch (Exception e) {
            LOGGER.fine("Marshalling Exception:" + e);
        }
        return null;
    }

    public static String getMetadataFromFile(String path) {
        String data = StringUtils.EMPTY;
        File file = new File(path.trim());
        try {
            data = FileUtils.readFileToString(file, "UTF-8");
        } catch (IOException e) {
            LOGGER.fine("Error occurred in reading file " + e);
            return StringUtils.EMPTY;
        }
        LOGGER.fine("data from file is " + data);
        return data;
    }

    public static List<String> configureFromMetadata(String metadata) throws Exception {

        List<String> metadataUrlValues = new ArrayList<String>();
        metadata = metadata.replaceAll("[^\\x20-\\x7e]", "");
        MoIDPMetadata idpMetadata = new MoIDPMetadata(metadata);
        String idpEntityId = "";
        String ssoBinding = "HttpRedirect";
        String ssoUrl = "";
        String sloBinding = "HttpRedirect";
        String sloUrl = "";
        String nameIdFormat = "";

        try {

            idpEntityId = idpMetadata.getEntityId();

            nameIdFormat = StringUtils.defaultIfBlank(idpMetadata.nameIdFormat,
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

            if (idpMetadata.getSingleSignOnServices().containsKey(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                ssoBinding = "HttpRedirect";
                ssoUrl = idpMetadata.getSingleSignOnServices().get(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            } else {
                ssoBinding = "HttpPost";
                ssoUrl = idpMetadata.getSingleSignOnServices().get(SAMLConstants.SAML2_POST_BINDING_URI);
            }
            if (idpMetadata.getSingleLogoutServices().size() > 0) {
                if (idpMetadata.getSingleLogoutServices().containsKey(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                    sloBinding = "HttpRedirect";
                    sloUrl = idpMetadata.getSingleLogoutServices().get(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                } else {
                    sloBinding = "HttpPost";
                    sloUrl = idpMetadata.getSingleLogoutServices().get(SAMLConstants.SAML2_POST_BINDING_URI);
                }
            }

            metadataUrlValues.add(idpEntityId);
            metadataUrlValues.add(nameIdFormat);
            metadataUrlValues.add(ssoUrl);
            metadataUrlValues.add(sloUrl);
            String x509Certificate = idpMetadata.getSigningCertificates().get(0);
            metadataUrlValues.add(x509Certificate);
        } catch (Exception e) {
            LOGGER.fine("Error Occured while updating attributes" + e);
            throw new Exception("Can not save IDP configurations", e);
        }
        return metadataUrlValues;
    }
    @RequirePOST
    @SuppressWarnings("unused")
    public HttpResponse doMoSamlAuth(final StaplerRequest request, final StaplerResponse response) throws IOException {
        String redirectUrl = StringUtils.EMPTY;
        boolean checkIdpInitiatedFlow = false;

        String relayStateFromIdP = request.getParameter(MoSAMLUtils.RELAY_STATE_PARAM);

        String[] parts = relayStateFromIdP.split("\\|", 2);
        String nonce = parts[0];
        String flowType = parts[1];

        // Remove the nonce value from the HashSet to prevent replay attacks
        if (nonceSet.contains(nonce)) {
            nonceSet.remove(nonce);
        } else {
            LOGGER.fine("Error in Nonce value, Repeated SAML response: ");
            checkIdpInitiatedFlow = true;
        }

        if (!StringUtils.isEmpty(flowType) && flowType.equals("testidpconfiguration")) {
            redirectUrl = URLDecoder.decode(flowType, "UTF-8");
        }
        if(StringUtils.isEmpty(redirectUrl)){
            redirectUrl = getBaseUrl();
        }
        LOGGER.fine("Relay state is "+ redirectUrl);
        recreateSession(request);
        LOGGER.fine("Reading SAML Response");
        String username = "";
        String email = "";
        MoSAMLPluginSettings settings = getMoSAMLPluginSettings();
        MoSAMLResponse moSAMLResponse ;
        MoSAMLManager moSAMLManager = new MoSAMLManager();
        MoSAMLTemplateManager moSAMLTemplateManager = new MoSAMLTemplateManager(getMoSAMLPluginSettings());

        try {
            moSAMLResponse = moSAMLManager.readSAMLResponse(request, response,settings);
            if(checkIdpInitiatedFlow && moSAMLResponse.getInResponseTo() != null ){
                throw new MoSAMLException("Invalid Response", MoSAMLException.SAMLErrorCode.RESPONDER);
            }

            if (StringUtils.equals(flowType, "testidpconfiguration")) {
                LOGGER.fine("Showing Test Configuration Result");
                return moSAMLTemplateManager.showTestConfigurationResult(moSAMLResponse, request, response);
            }
            LOGGER.fine("Not showing test config");

            if (moSAMLResponse.getAttributes().get(settings.getUsernameAttribute()) != null
                    && moSAMLResponse.getAttributes().get(settings.getUsernameAttribute()).length == 1) {
                username = moSAMLResponse.getAttributes().get(settings.getUsernameAttribute())[0];
                username = loadUserName(username);
            }

            if (moSAMLResponse.getAttributes().get(settings.getEmailAttribute()) != null
                    && moSAMLResponse.getAttributes().get(settings.getEmailAttribute()).length == 1) {
                email = moSAMLResponse.getAttributes().get(settings.getEmailAttribute())[0];
            }

            LOGGER.fine("Username received: " + username + " email received = " + email);
            LOGGER.fine("Login Method for Users is:" + settings.getLoginType());
            if (settings.getLoginType().equals("usernameLogin") && StringUtils.isNotBlank(username)) {
                LOGGER.fine("User name Login Selected");
                username=handleUsernameLogin(username, settings);
                User user = User.getById(username, false);

                if (user == null && !settings.getUserCreate()) {
                    LOGGER.fine("User does not exist");
                    String errorMessage = "<div class=\"alert alert-danger\">User does not Exist</div><br>";
                    return doMoLogin(request, response, errorMessage);
                } else if (user == null && settings.getUserCreate()) {
                    username=handleUsernameLogin(username, settings);
                    User newUser = userCreateSAML( username, email, settings, moSAMLResponse);
                    if (newUser == null) {
                        LOGGER.fine("User creation Failed");
                        String errorMessage = "<div class=\"alert alert-danger\">User creation Failed. Please view logs for more information.<br>";
                        return doMoLogin(request, response, errorMessage);
                    } else {
                        return createSessionAndLoginUser(newUser,request,response, true,settings, redirectUrl);
                    }
                } else {
                    return createSessionAndLoginUser(user,request,response,false,settings,redirectUrl);
                }

            } else if(settings.getLoginType().equals("emailLogin") && StringUtils.isNotBlank(email)){
                LOGGER.fine("Email Login Selected");
                ArrayList<String> usernameList = handleEmailLogin(request, response, email, settings, moSAMLResponse);
                if(usernameList.size() > 1){
                    LOGGER.fine("Multiple Mail Addresses");
                    String errorMessage = "<div class=\"alert alert-danger\">More than one user found with this email address.</div><br>";
                    return doMoLogin(request,response,errorMessage);}
                if (usernameList.size()==0 && !settings.getUserCreate()) {
                    LOGGER.fine("User does not exist and user creation is disabled");
                    String errorMessage = "<div class=\"alert alert-danger\">User does not Exist</div><br>";
                    return doMoLogin(request, response, errorMessage);
                } else if (usernameList.size()==0 && settings.getUserCreate()) {
                    User newUser = userCreateSAML(username, email, settings, moSAMLResponse);
                    if (newUser == null) {
                        LOGGER.fine("User creation Failed");
                        String errorMessage = "<div class=\"alert alert-danger\">User creation Failed.<br>";
                        return doMoLogin(request, response, errorMessage);
                    } else {
                        return createSessionAndLoginUser(newUser,request,response,true,settings,redirectUrl);
                    }
                } else {
                    User user= User.getById(usernameList.get(0),false);
                    return createSessionAndLoginUser(user,request,response,false,settings,redirectUrl);

                }

            }
            else {
                LOGGER.fine("Invalid login Attribute");
                String errorMessage = "<div class=\"alert alert-danger\">Username not received in the SAML Response. Please check your configuration.</div><br>";
                return doMoLogin(request, response, errorMessage);
            }

        }
        catch(MoSAMLException e){

            if (StringUtils.contains(flowType, "testidpconfiguration")) {
                LOGGER.fine("Error in Test Configuration Result");
                tcf = new TestConfigurationFailed(e.getErrorCode().getCode(), e.getErrorCode().getMessage(), e.getResolution(), e.getMessage());
                return HttpResponses.redirectTo("testConfigurationFailed");
            }

            LOGGER.fine("Invalid response");
            String errorMessage = "<div class=\"alert alert-danger\">Error occurred while reading response.</div><br>";
            return doMoLogin(request, response, errorMessage);

        }
        catch (Exception ex) {
            LOGGER.fine("Invalid response");
            String errorMessage = "<div class=\"alert alert-danger\">Error occurred while reading response.</div><br>";
            return doMoLogin(request, response, errorMessage);
        }
    }

    @SuppressWarnings("unused")
    public TestConfigurationFailed getTestConfigurationFailed() {
        return tcf;
    }

    private String loadUserName(String username) {
        MoSAMLPluginSettings settings = getMoSAMLPluginSettings();
        if ("lowercase".compareTo(settings.getUsernameCaseConversion()) == 0) {
            username = username.toLowerCase();
        } else if ("uppercase".compareTo(settings.getUsernameCaseConversion()) == 0) {
            username = username.toUpperCase();
        }
        return username;
    }

    private ArrayList<String> handleEmailLogin(StaplerRequest request, StaplerResponse response, String email, MoSAMLPluginSettings settings, MoSAMLResponse moSAMLResponse) {
        ArrayList<String> usernameList= new ArrayList<String>();
        try {
            Collection<User> users = User.getAll();

            for (User user : users) {
                String emailAddress = user.getProperty(Mailer.UserProperty.class).getAddress();
                if (emailAddress != null&&emailAddress.equals(email)) {
                    usernameList.add(user.getId());
                }
            }

        } catch (Exception e) {
            LOGGER.fine("Error Occurred while searching for user"+e);
            return usernameList;
        }
        return usernameList;
    }

    private User userCreateSAML( String username, String email, MoSAMLPluginSettings settings, MoSAMLResponse moSAMLResponse) {
            User new_user=null;
        try {
                new_user = User.getById(username, true);
                LOGGER.fine("Updating user attributes");

                attributeUpdate(settings, new_user, moSAMLResponse,settings.getLoginType());

                if(new_user!=null ){
                    new_user.addProperty(new Mailer.UserProperty(email));
                }

        } catch (IOException e) {
            e.printStackTrace();
            return new_user;
        }
        return new_user;
    }

    public void attributeUpdate(MoSAMLPluginSettings settings, User user, MoSAMLResponse moSAMLResponse,String loginType) {
        try {
            if (user != null) {
                LOGGER.fine("user is not null");
                modifyUserSamlCustomAttributes(user, settings, moSAMLResponse);
            }
        }catch (Exception e)
        {
            LOGGER.fine("Error occurred."+e);
        }
    }

    private void modifyUserSamlCustomAttributes(User user, MoSAMLPluginSettings settings, MoSAMLResponse moSAMLResponse) {
        LOGGER.fine("Adding custom Attributes");

        if (!settings.getSamlCustomAttributes().isEmpty() && user != null) {
            MoSAMLuserProperty userProperty = new MoSAMLuserProperty(new ArrayList<>());
            Map<String, String[]> responseSAMLAttributes = moSAMLResponse.getAttributes();
            for (String name: responseSAMLAttributes.keySet()){
                String key = name.toString();
                String value = Arrays.toString(responseSAMLAttributes.get(name));
            }

            for (MoAttributeEntry attributeEntry : getSamlCustomAttributes()) {
                LOGGER.fine("attributeEntry"+attributeEntry);
                if (attributeEntry instanceof MoAttribute) {
                    MoAttribute attr = (MoAttribute) attributeEntry;

                    MoSAMLuserProperty.Attribute item = new MoSAMLuserProperty.Attribute(attr.getName(), attr.getDisplayName());
                    LOGGER.fine(attr.getName()+ attr.getDisplayName()+"sssS");
                    if (responseSAMLAttributes.containsKey(attr.getName())) {
                        String AttributeVal = responseSAMLAttributes.get(attr.getName())[0];
                        LOGGER.fine("AttributeVal"+AttributeVal);
                        item.setValue(AttributeVal);
                    } else {
                        item.setValue("");
                    }
                    userProperty.getAttributes().add(item);
                }

            }
            try {
                user.addProperty(userProperty);
            } catch (IOException e) {
                LOGGER.fine("Error Occurred while updating attributes" + e);
            }
        }
    }


    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents((AuthenticationManager) authentication -> {
            if (authentication instanceof MoSAMLAuthenticationTokenInfo) {
                return authentication;
            }
            throw new BadCredentialsException("Invalid Auth type " + authentication);
        });
    }

    private String handleUsernameLogin(String username, MoSAMLPluginSettings settings) {
        String regexPattern = "";
        if (StringUtils.isNotBlank(settings.getRegexPattern()) && settings.getEnableRegexPattern()) {
            LOGGER.fine("Regex Login for Username");
            regexPattern = settings.getRegexPattern();
            try {
                Pattern pattern = Pattern.compile(StringUtils.trimToEmpty(regexPattern));
                Matcher matcher = pattern.matcher(username);
                LOGGER.fine(String.valueOf(matcher));
                if (matcher.find()) {
                    username = StringUtils.EMPTY;
                    if (matcher.groupCount() > 0) {
                        StringBuffer buf = new StringBuffer();
                        for (int i = 1; i <= matcher.groupCount(); ++i) {
                            buf.append(matcher.group(i));
                        }
                       username = buf.toString();
                    } else {
                        username = matcher.group();
                    }
                }
            } catch (Exception e) {
                LOGGER.fine("Can't sign in regex pattern exception occured" + e);
                return username;
            }
        }
       return username;

    }
    public  HttpResponse createSessionAndLoginUser(User user, StaplerRequest request,StaplerResponse response, Boolean newUserCreated,MoSAMLPluginSettings settings, String redirectUrl){
        if (user != null) {
            LOGGER.fine("User exists for Username: " + user.getId());

            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            session = request.getSession(true);

            session.setAttribute("sessionIndex", MoSAMLUtils.generateRandomAlphaNumericKey(16));
            session.setAttribute("nameID", user.getId());

            UserDetails details = user.getUserDetailsForImpersonation2();
            LOGGER.fine("UserDetails"+details);

            MoSAMLUserInfo userInfo = new MoSAMLUserInfo(user.getId(), details.getAuthorities());
            MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
            SecurityContextHolder.getContext().setAuthentication(tokenInfo);
            SecurityListener.fireAuthenticated2(userInfo);
            SecurityListener.fireLoggedIn(user.getId());
           return HttpResponses.redirectTo(redirectUrl);

        } else {
            LOGGER.fine("User does not exist.");
            String errorMessage = "<div class=\"alert alert-danger\">User does not exist..</div><br>";
            return doMoLogin(request,response,errorMessage);
        }
    }
    @SuppressWarnings("unused")
    public String getMetadataUrl() {
        return metadataUrl;
    }
    @SuppressWarnings("unused")
    public String getMetadataFilePath() {
        return metadataFilePath;
    }
    @SuppressWarnings("unused")
    public String getIdpEntityId() {
        return idpEntityId;
    }
    @SuppressWarnings("unused")
    public String getSsoUrl() {
        return ssoUrl;
    }
    @SuppressWarnings("unused")
    public String getPublicx509Certificate() {
        return publicx509Certificate;
    }
    @SuppressWarnings("unused")
    public String getUsernameAttribute() {
        if (StringUtils.isEmpty(usernameAttribute)) {
            return "NameID";
        } else {
            return usernameAttribute;
        }
    }
    @SuppressWarnings("unused")
    public String getEmailAttribute() {
        if (StringUtils.isEmpty(emailAttribute)) {
            return "NameID";
        } else {
            return emailAttribute;
        }
    }

    public String getCustomLoginTemplate() throws IOException {
        return IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");
    }
    /**
     * check if a request contains a session, if so, it invalidate the session and create new one to avoid session
     * fixation.
     * @param request request.
     */
    private void recreateSession(StaplerRequest request) {
        HttpSession session = request.getSession(false);
        if(session != null){
            LOGGER.fine("Invalidate previous session");
            // avoid session fixation
            session.invalidate();
        }
        request.getSession(true);
    }
    @SuppressWarnings("unused")
    public String getNameIDFormat() {
        return nameIDFormat;
    }

    @SuppressWarnings("unused")
    public Boolean getUserCreate() {
        return userCreate;
    }

    @SuppressWarnings("unused")
    public Boolean getForceAuthn(){ return forceAuthn; }

    @SuppressWarnings("unused")
    public String getRegexPattern() {
        return regexPattern;
    }

    @SuppressWarnings("unused")
    public Boolean getEnableRegexPattern() {
        return enableRegexPattern;
    }

    @SuppressWarnings("unused")
    public String getSsoBindingType() {
        return ssoBindingType;
    }

    @SuppressWarnings("unused")
    public String getUsernameCaseConversion() {
        return usernameCaseConversion;
    }

    @SuppressWarnings("unused")
    public String getAuthnContextClass() {
        return authnContextClass;
    }

    @NonNull
    public List<MoAttributeEntry> getSamlCustomAttributes() {
        if (samlCustomAttributes == null) {
            return java.util.Collections.emptyList();
        }
        return samlCustomAttributes;
    }

    private MoSAMLPluginSettings getMoSAMLPluginSettings() {
        MoSAMLPluginSettings settings = new MoSAMLPluginSettings(idpEntityId, ssoUrl, publicx509Certificate, usernameCaseConversion, usernameAttribute, emailAttribute, nameIDFormat,
                loginType, regexPattern, enableRegexPattern, signedRequest, userCreate, forceAuthn, ssoBindingType,samlCustomAttributes,authnContextClass,crowdURL,crowdApplicationName,crowdApplicationPassword);
        return settings;
    }

    public static final MoSAMLAddIdp.DescriptorImpl DESCRIPTOR = new MoSAMLAddIdp.DescriptorImpl();

    @Override
    public String toString() {
        return "{" +
                "\"spEntityId:\": \"" + getBaseUrl() + '\"' +
                ", \"audienceURI:\": \"" + getBaseUrl() + '\"' +
                ", \"acsURL:\": \"" + getBaseUrl() + "securityRealm/moSamlAuth" + '\"' +
                ", \"spLogoutURL:\": \"" + getBaseUrl() + "securityRealm/logout" + '\"' +
                ", \"idpEntityId\": \"" + idpEntityId + '\"' +
                ", \"ssoUrl\": \"" + ssoUrl + '\"' +
                ", \"metadataUrl\": \"" + metadataUrl + '\"' +
                ", \"metadataFilePath\": \"" + metadataFilePath + '\"' +
                ", \"publicx509Certificate\": \"" + publicx509Certificate + '\"' +
                ", \"usernameAttribute\": \"" + usernameAttribute + '\"' +
                ", \"fullnameAttribute\": \"" + fullnameAttribute + '\"' +
                ", \"usernameCaseConversion\": \"" + usernameCaseConversion + '\"' +
                ", \"userAttributeUpdate\": \"" + userAttributeUpdate + '\"' +
                ", \"emailAttribute\": \"" + emailAttribute + '\"' +
                ", \"nameIDFormat\": \"" + nameIDFormat + '\"' +
                ", \"sslUrl\": \"" + sslUrl + '\"' +
                ", \"loginType\": \"" + loginType + '\"' +
                ", \"regexPattern\": \"" + regexPattern + '\"' +
                ", \"enableRegexPattern\": \"" + enableRegexPattern + '\"' +
                ", \"signedRequest\": \"" + signedRequest + '\"' +
                ", \"splitnameAttribute\": \"" + splitnameAttribute + '\"' +
                ", \"userCreate\": \"" + userCreate + '\"' +
                ", \"forceAuthn\": \"" + forceAuthn + '\"' +
                ", \"ssoBindingType\": \"" + ssoBindingType + '\"' +
                ", \"sloBindingType\": \"" + sloBindingType + '\"' +
                ", \"samlCustomAttributes\":"  + samlCustomAttributes +
                ", \"newUserGroup\": \"" + newUserGroup + '\"' +
                ", \"authnContextClass\": \"" + authnContextClass + '\"' +
                ", \"disableDefaultLogin\": \"" + "false" + '\"' +
                ", \"crowdURL\":\"" + crowdURL + '\"' +
                ", \"crowdApplicationName\":\"" + crowdApplicationName + '\"' +
                ", \"crowdApplicationPassword\":\"" + crowdApplicationPassword + '\"' +
                '}';
    }

    public void setCrowdURL(String crowdURL) {
        this.crowdURL = crowdURL;
    }

    public String getCrowdURL() {
        return crowdURL;
    }

    public void setCrowdApplicationName(String crowdApplicationName) {
        this.crowdApplicationName = crowdApplicationName;
    }

    public String  getCrowdApplicationName() {
       return crowdApplicationName;
    }

    public void setCrowdApplicationPassword(Secret crowdApplicationPassword) {
        this.crowdApplicationPassword = crowdApplicationPassword;
    }
   public Secret getCrowdApplicationPassword() {
        return crowdApplicationPassword;
    }


    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }

        @Override
        public String getDisplayName() {
            return "miniOrange SAML 2.0";
        }

        public Boolean checkFormHasData(net.sf.json.JSONObject formData){

            return  formData.has("idpEntityId") &&
                    formData.has("ssoUrl") &&
                    formData.has("metadataUrl") &&
                    formData.has("metadataFilePath") &&
                    formData.has("publicx509Certificate") &&
                    formData.has("usernameCaseConversion") &&
                    formData.has("usernameAttribute") &&
                    formData.has("emailAttribute") &&
                    formData.has("fullnameAttribute") &&
                    formData.has("nameIDFormat") &&
                    formData.has("sslUrl") &&
                    formData.has("loginType") &&
                    formData.has("regexPattern") &&
                    formData.has("enableRegexPattern") &&
                    formData.has("signedRequest") &&
                    formData.has("splitnameAttribute") &&
                    formData.has("userCreate") &&
                    formData.has("forceAuthn") &&
                    formData.has("ssoBindingType") &&
                    formData.has("sloBindingType") &&
                    formData.has("userAttributeUpdate") &&
                    formData.has("authnContextClass");
        }


        @Override
        public SecurityRealm newInstance(StaplerRequest req, net.sf.json.JSONObject formData) {
            SecurityRealm oldRealm = Jenkins.get().getSecurityRealm();
            MoSAMLAddIdp Realm;
            if (checkFormHasData(formData) && oldRealm instanceof MoSAMLAddIdp) {
                LOGGER.log(Level.FINE, "form has existing data"  );
                List<MoAttributeEntry> attributeList  = new ArrayList<MoAttributeEntry>();

                try{
                    String samlCustomAttributesString = (formData.get("samlCustomAttributes") != null ? StringUtils.defaultIfBlank(formData.get("samlCustomAttributes").toString(), "") : "");
                    if(samlCustomAttributesString.startsWith("\"")){
                        samlCustomAttributesString = samlCustomAttributesString.substring(1, samlCustomAttributesString.length() - 1);
                    }
                    if(samlCustomAttributesString.startsWith("[")) {
                        JSONArray jsonArray = formData.getJSONArray("samlCustomAttributes");
                        Iterator iterator = jsonArray.iterator();
                        while (iterator.hasNext()) {
                            net.sf.json.JSONObject jsonObject = (net.sf.json.JSONObject) iterator.next();
                            MoAttribute attribute = new MoAttribute(jsonObject.getString("name"), jsonObject.getString("displayName"));
                            attributeList.add(attribute);
                        }
                    }
                    else if (samlCustomAttributesString.startsWith("{")){
                        net.sf.json.JSONObject jsonObject = formData.getJSONObject("samlCustomAttributes");
                        MoAttribute attribute = new MoAttribute(jsonObject.getString("name"), jsonObject.getString("displayName"));
                        attributeList.add(attribute);
                    }

                }
                catch (Exception e) {
                    LOGGER.fine("Error is  " + e.getMessage());
                }

                MoSAMLAddIdp oldMoSAMLAddIdp = (MoSAMLAddIdp) oldRealm;
                try {
                    Realm = new MoSAMLAddIdp(
                            StringUtils.defaultIfBlank(formData.get("idpEntityId").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("ssoUrl").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("metadataUrl").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("metadataFilePath").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("publicx509Certificate").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("usernameCaseConversion").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("usernameAttribute").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("emailAttribute").toString(),""),
                            StringUtils.defaultIfBlank(formData.get("fullnameAttribute").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("nameIDFormat").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("sslUrl").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("loginType").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("regexPattern").toString(), ""),
                            Boolean.parseBoolean(formData.get("enableRegexPattern").toString()),
                            Boolean.parseBoolean(formData.get("signedRequest").toString()),
                            Boolean.parseBoolean(formData.get("splitnameAttribute").toString()),
                            Boolean.parseBoolean(formData.get("userCreate").toString()),
                            Boolean.parseBoolean(formData.get("forceAuthn").toString()),
                            StringUtils.defaultIfBlank(formData.get("ssoBindingType").toString(), ""),
                            StringUtils.defaultIfBlank(formData.get("sloBindingType").toString(), ""),
                            attributeList,
                            Boolean.parseBoolean(formData.get("userAttributeUpdate").toString()),
                            StringUtils.defaultIfBlank(formData.get("authnContextClass").toString(), ""),
                            formData.has("crowdURL")?formData.getString("crowdURL"):StringUtils.defaultIfBlank(oldMoSAMLAddIdp.getCrowdURL(), ""),
                            formData.has("crowdApplicationName")? formData.getString("crowdApplicationName"):StringUtils.defaultIfBlank(oldMoSAMLAddIdp.getCrowdApplicationName(), ""),
                            formData.has("crowdApplicationPassword")?Secret.fromString(formData.getString("crowdApplicationPassword")):Secret.fromString(StringUtils.defaultIfBlank(oldMoSAMLAddIdp.getCrowdApplicationPassword().toString(), ""))
                    );
                } catch (Exception e) {
                    LOGGER.fine(" Error in loading security realm : " + e.getMessage());
                    throw new RuntimeException(e);
                }

            } else if (oldRealm instanceof MoSAMLAddIdp) {
                LOGGER.log(Level.FINE, " Loading old Realm ");
                Realm = (MoSAMLAddIdp) oldRealm;
            } else {
                LOGGER.fine("Creating empty realm");
                try {
                    Realm = new MoSAMLAddIdp("","","","","","","","","","","","","",false,
                            false,false,true, false,"","",null,false,"","","",Secret.fromString("")
                    );
                } catch (Exception e) {
                    LOGGER.fine("Unable to create Security realm object , error is " + e.getMessage());
                    throw new RuntimeException(e);
                }
            }
            return Realm;
        }

        private static void checkAdminPermission() {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        }
        private static void persistChanges() throws IOException {
            Jenkins.get().save();
        }
        @RequirePOST
        @Restricted(NoExternalUse.class)
        public void doRealmSubmit(StaplerRequest req, StaplerResponse rsp, net.sf.json.JSONObject json) throws ServletException, IOException, ServletException {
            checkAdminPermission();
            LOGGER.log(Level.FINE, "Saving realm values : " + json.toString());
            SecurityRealm Realm = this.newInstance(req, json);
            Jenkins.get().setSecurityRealm(Realm);
            persistChanges();
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckIdpEntityId(@QueryParameter String idpEntityId) {
            checkAdminPermission();
            if (StringUtils.isEmpty(idpEntityId)) {
                return FormValidation.error("The Entity ID Can not be kept blank.");
            }
            return FormValidation.ok();
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckSsoUrl(@QueryParameter String ssoUrl) {
            checkAdminPermission();
            if (StringUtils.isEmpty(ssoUrl)) {
                return FormValidation.error("The Single Sign On URL Can not be kept blank.");
            }
            try {
                new URL(ssoUrl);
            } catch (MalformedURLException e) {
                return FormValidation.error("The URL is malformed.", e);
            }
            return FormValidation.ok();
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckUsernameAttribute(@QueryParameter String usernameAttribute, @QueryParameter String loginType) {
            checkAdminPermission();
            if (StringUtils.isEmpty(usernameAttribute) && loginType.equals("usernameLogin")) {
                return FormValidation.warning("Username Can not kept blank");
            }
            return FormValidation.ok();
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckEmailAttribute(@QueryParameter String emailAttribute, @QueryParameter String loginType) {
            checkAdminPermission();
            if (StringUtils.isEmpty(emailAttribute) && loginType.equals("emailLogin")) {
                return FormValidation.warning("Email Address Can not kept blank");
            }
            return FormValidation.ok();
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckPublicx509Certificate(@QueryParameter String publicx509Certificate) {
            checkAdminPermission();
            if (StringUtils.isEmpty(publicx509Certificate)) {
                return FormValidation.error("Certificate cannot be kept blank.");
            }
            else if(StringUtils.isNotBlank(publicx509Certificate))
            {
                Boolean validCertificate= MoSAMLUtils.isValidPublicCertificate(publicx509Certificate);
                LOGGER.fine("is certificate valid:"+validCertificate);
                if(validCertificate){
                    return FormValidation.ok();
                }
                else
                    return FormValidation.error("Invalid Certificate");
            }
            return FormValidation.error("Certificate validation failed.");
        }


        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckRegexPattern(@QueryParameter Boolean enableRegexPattern, @QueryParameter String regexPattern) {
            checkAdminPermission();
            if (enableRegexPattern && StringUtils.isEmpty(regexPattern)) {
                return FormValidation.error("The Regex Pattern is not Valid");
            } else {
                return FormValidation.ok();
            }
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doUserCreate(@QueryParameter Boolean userCreate, @QueryParameter String emailAttribute, @QueryParameter String usernameAttribute) {
            checkAdminPermission();
            if (userCreate && StringUtils.isEmpty(emailAttribute) && StringUtils.isEmpty(usernameAttribute)) {
                return FormValidation.error("Email and Username Attributes are required.");
            } else {
                return FormValidation.ok();
            }
        }

        public String getBaseUrl() {
            String rootURL= get().getRootUrl();
            if(rootURL.endsWith("/")){
                rootURL= rootURL.substring(0,rootURL.length()-1);
            }
            return rootURL;
        }

        @POST
        public FormValidation doCheckSslUrl(@QueryParameter String sslUrl) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckUserAttributeUpdate(@QueryParameter Boolean userAttributeUpdate) {
            checkAdminPermission();
            if (! userAttributeUpdate) {
                return FormValidation.warning("Available in premium version");
            }
            return FormValidation.ok();
        }
        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckSignedRequest(@QueryParameter Boolean signedRequest) {
            checkAdminPermission();
            if (! signedRequest) {
                return FormValidation.warning("Available in premium version");
            }
            return FormValidation.ok();
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckSplitnameAttribute(@QueryParameter Boolean splitnameAttribute) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }
        @POST
        public FormValidation doCheckDisableDefaultLogin(@QueryParameter Boolean disableDefaultLogin) {
            checkAdminPermission();
            if (! disableDefaultLogin) {
                return FormValidation.warning("Available in premium version");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckGroupAttribute(@QueryParameter String groupAttribute) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }
        @POST
        public FormValidation doCheckNewUserGroup(@QueryParameter String newUserGroup) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }

        @POST
        public FormValidation doCheckUpdateUserFromCrowd(@QueryParameter Boolean updateUserFromCrowd) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }

        @POST
        public FormValidation doCheckUpdateNestedGroupsFromCrowd(@QueryParameter Boolean updateNestedGroupsFromCrowd) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }
        @POST
        public FormValidation doCheckFullnameAttribute(@QueryParameter String updateNestedGroupsFromCrowd) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }

        @POST
        public FormValidation doCheckEnableCustomLoginTemplate(@QueryParameter Boolean enableCustomLoginTemplate) {
            checkAdminPermission();
            return FormValidation.warning("Available in premium version");
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doPerformTestConfiguration(@QueryParameter String idpEntityId, @QueryParameter String ssoUrl, @QueryParameter String publicx509Certificate) {
            checkAdminPermission();
            if(StringUtils.isEmpty(idpEntityId) || StringUtils.isEmpty(ssoUrl) || StringUtils.isEmpty(publicx509Certificate)) {
                LOGGER.fine("Entity ID is " + idpEntityId);
                LOGGER.fine("ssoUrl is " + ssoUrl);
                LOGGER.fine("publicx509Certificate is " + publicx509Certificate);
                return FormValidation.error("Save the idp configurations first. Could not perform test config");
            }
            LOGGER.fine("Test config called..");
            String testConfigUrl = getBaseUrl() + "/securityRealm/moSamlLogin?from=testidpconfiguration";
            return FormValidation.okWithMarkup("Click " + "<a href='"+ testConfigUrl+ "' target='_blank' >here</a>"+ " to see the test configurations result.");
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doValidateMetadataUrl(@QueryParameter String metadataUrl) throws Exception {
            checkAdminPermission();
            String metadata = sendGetRequest(metadataUrl, null);
            try{
                List<String> metadataUrlValues = configureFromMetadata(metadata);
            }catch (Exception e){
                LOGGER.fine("Invalid metadata Url" + e);
                return FormValidation.error("Invalid metadata Url");
            }
            return FormValidation.okWithMarkup("Valid metadata Url, please hit save button");
        }
        @POST
        @SuppressWarnings("unused")
        public FormValidation doValidateMetadataFile(@QueryParameter String metadataFilePath) throws Exception {
            checkAdminPermission();
            String metadata = getMetadataFromFile(metadataFilePath);
            try{
                List<String> metadataUrlValues = configureFromMetadata(metadata);
            }catch (Exception e){
                LOGGER.fine("File not found or wrong file extension");
                return FormValidation.error("File not found or wrong file extension");
            }
            return FormValidation.okWithMarkup("Validation successful, please hit save button");
        }
    }

}
