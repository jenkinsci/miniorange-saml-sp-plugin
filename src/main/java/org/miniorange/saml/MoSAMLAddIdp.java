package org.miniorange.saml;

import hudson.model.BooleanParameterDefinition;
import org.apache.commons.io.FileUtils;
import org.miniorange.saml.MoIDPMetadata;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import hudson.util.Secret;
import org.acegisecurity.Authentication;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.BooleanUtils;

import org.json.JSONException;
import org.json.JSONObject;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.apache.commons.io.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;


import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.nio.file.Files;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.acegisecurity.BadCredentialsException;
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

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.conn.ssl.SSLContextBuilder;
import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.config.Registry;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import java.net.ProxySelector;
import org.apache.http.impl.client.HttpClients;

public class MoSAMLAddIdp extends SecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(MoSAMLAddIdp.class.getName());
    public static final String MO_SAML_SP_AUTH_URL = "securityRealm/moSamlAuth";
    public static final String DEFAULT_CUSTOMER_KEY="16555";
    public static final String DEFAULT_API_KEY="fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq";
    public static final String AUTH_BASE_URL = "https://auth.miniorange.com/moas";
    public static final String NOTIFY_API = AUTH_BASE_URL + "/api/notify/send";
    public static final String MO_SAML_JENKINS_LOGIN_ACTION = "securityRealm/moLoginAction";
    public static final String MO_SAML_SSO_FORCE_STOP = "securityRealm/moSAMLSingleSignOnForceStop";
    public static final String MO_SAML_SP_METADATA_URL = "securityRealm/mospmetadata";
    public static final String MO_SAML_SP_CERTIFCATE_DOWNLOAD = "securityRealm/downloadCertificate";

    public static final String MO_SAML_SSO_LOGIN_ACTION = "securityRealm/moSamlLogin";


    private static final String LOGIN_TEMPLATE_PATH = "/templates/mosaml_login_page_template.html";
    private static final String AUTO_REDIRECT_TO_IDP_TEMPLATE_PATH = "/templates/AutoRedirectToIDPTemplate.html";
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
                        String newUserGroup,
                        String authnContextClass
    ) throws Exception {
        super();
        this.metadataUrl = metadataUrl;
        this.metadataFilePath = metadataFilePath;
        if (!StringUtils.isEmpty(metadataUrl) || !StringUtils.isEmpty(metadataFilePath) ) {
            String metadata = (!StringUtils.isEmpty(metadataUrl) ? sendGetRequest(metadataUrl) : getMetadataFromFile(metadataFilePath));
            List<String> metadataUrlValues = configureFromMetadata(metadata);
            if (metadataUrlValues != null) {

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
            manualConfig(idpEntityId,ssoUrl,publicx509Certificate);
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
        this.userCreate = (userCreate != null) ? userCreate : false;
        this.forceAuthn = (forceAuthn != null) ? forceAuthn : false;
        this.ssoBindingType = (ssoBindingType != null) ? ssoBindingType : "HttpRedirect";
        this.sloBindingType =  (sloBindingType != null) ? sloBindingType : "HttpRedirect";
        this.samlCustomAttributes = samlCustomAttributes;
        this.userAttributeUpdate = (userAttributeUpdate != null) ? userAttributeUpdate : false;
        this.fullnameAttribute = fullnameAttribute;
        this.newUserGroup= newUserGroup;
        this.authnContextClass=(authnContextClass != null) ? authnContextClass : "None";
    }

    private void manualConfig(String idpEntityId, String ssoUrl, String publicx509Certificate) throws Exception {
        if(StringUtils.isEmpty(idpEntityId)||StringUtils.isEmpty(ssoUrl) || StringUtils.isEmpty(publicx509Certificate) ){
            LOGGER.fine("Could not save IDP configurations");
            throw new Exception("Can not save IDP configurations");
        }
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
    public String getPostLogOutUrl(StaplerRequest req, Authentication auth) {

        return "/securityRealm/moLogin";
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
                            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                            authorities.add(AUTHENTICATED_AUTHORITY);
                            MoSAMLUserInfo userInfo = new MoSAMLUserInfo(username, authorities.toArray(new GrantedAuthority[authorities.size()]));
                            MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
                            SecurityContextHolder.getContext().setAuthentication(tokenInfo);
                            SecurityListener.fireAuthenticated(userInfo);
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

    private String calculateSafeRedirect( String referer) {
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

    public void doMoSamlLogin(final StaplerRequest request, final StaplerResponse response, @Header("Referer") final String referer) {
        recreateSession(request);
        String redirectOnFinish = StringUtils.EMPTY;
        if(StringUtils.isEmpty(request.getQueryString())){
             redirectOnFinish = calculateSafeRedirect(referer);
        }
        else{
            redirectOnFinish = request.getQueryString();
        }

        LOGGER.fine("relay state " + redirectOnFinish);
        request.getSession().setAttribute(REFERER_ATTRIBUTE, redirectOnFinish);

        LOGGER.fine("in doMoSamlLogin");
        MoSAMLManager moSAMLManager = new MoSAMLManager(getMoSAMLPluginSettings());
        moSAMLManager.createAuthnRequestAndRedirect(request, response, redirectOnFinish,getMoSAMLPluginSettings());
    }

    private String getBaseUrl() {
        return get().getRootUrl();
    }

    private String getErrorUrl() {
        return get().getRootUrl() + MO_SAML_JENKINS_LOGIN_ACTION;
    }

    public String spMetadataURL() {
        return get().getRootUrl() + MO_SAML_SP_METADATA_URL;
    }


    @RequirePOST
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
                    j.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
                JSONObject json = new JSONObject();
                JSONObject success = new JSONObject();
                success.put("Status", "SUCCESS");
                success.put("Message", "Successfully disabled SSO");
                json.put("Message", success);
                response.setContentType(MediaType.APPLICATION_JSON);
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
            response.setContentType(MediaType.APPLICATION_JSON);
            response.setStatus(errorCode);
            response.getOutputStream().write(json.toString().getBytes(StandardCharsets.UTF_8));
            response.getOutputStream().close();
        } catch (JSONException | IOException e) {
            LOGGER.fine("An error occurred while sending json response" + e);
        }
    }

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
                response.setContentType(MediaType.APPLICATION_XML);
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
    public  void doDownloadCertificate(final StaplerRequest request, final StaplerResponse response) throws Exception {
        LOGGER.fine("Downloading SP Certificate.");
        try {
            MoSAMLPluginSettings moSAMLPluginSettings = getMoSAMLPluginSettings();
            String certificate = moSAMLPluginSettings.getPublicSPCertificate();
            response.setHeader("Content-Disposition", "attachment; filename=\"sp-certificate.crt\"");
            response.setHeader("Cache-Control", "max-age=0");
            response.setHeader("Pragma", "");
            response.setContentType(MediaType.APPLICATION_OCTET_STREAM);
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

    private static CloseableHttpClient getHttpClient() throws KeyStoreException, NoSuchAlgorithmException,
            KeyManagementException {
        HttpClientBuilder builder = HttpClientBuilder.create();
        SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, (arg0, arg1) -> true).build();
        SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(sslContext,
                SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        builder.setSSLSocketFactory(sslConnectionFactory);

        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", sslConnectionFactory)
                .register("http", PlainConnectionSocketFactory.INSTANCE)
                .build();

        HttpClientConnectionManager ccm = new BasicHttpClientConnectionManager(registry);

        builder.setConnectionManager(ccm);

        //return builder.build();
        SystemDefaultRoutePlanner routePlanner = new SystemDefaultRoutePlanner(ProxySelector.getDefault());
        CloseableHttpClient httpclient = HttpClients.custom().setRoutePlanner(routePlanner).setConnectionManager(ccm)
                .build();
        return httpclient;
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

    public static String sendGetRequest(String url) {
        String errorMsg = new String("Did not get metadata");
        try {
            LOGGER.info("MoHttpUtils sendGetRequest Sending GET request to " + url);
            CloseableHttpClient httpClient = getHttpClient();
            HttpGet getRequest = new HttpGet(url);
            org.apache.http.HttpResponse response = httpClient.execute(getRequest);
            LOGGER.info("Response for HTTP Request: " + response.toString() + " and Status Code: " + response
                    .getStatusLine().getStatusCode());

            if (response.getStatusLine().getStatusCode() == 200 && response.getEntity() != null) {
                LOGGER.info("Response Entity found. Reading Response payload.");
                String data = IOUtils.toString(new InputStreamReader((response.getEntity().getContent())));
                LOGGER.info("Response payload: " + data);
                httpClient.close();
                return data;
            } else {

                LOGGER.info("Response Entity NOT found. ");
                httpClient.close();
                return errorMsg;
            }
        } catch (Exception e) {
            LOGGER.info("error occur "+e);
            return errorMsg;
        }
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
    public HttpResponse doMoSamlAuth(final StaplerRequest request, final StaplerResponse response) throws IOException {
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        String redirectUrl = StringUtils.EMPTY;
        String relayState = calculateSafeRedirect(request.getParameter(MoSAMLUtils.RELAY_STATE_PARAM));
        if(!StringUtils.isEmpty(relayState)){
            redirectUrl= URLDecoder.decode(relayState, "UTF-8");
        }
        LOGGER.fine("Relay state is "+ redirectUrl);
        if(StringUtils.isEmpty(redirectUrl)){
            redirectUrl = getBaseUrl();
        }
        recreateSession(request);
        LOGGER.fine(" Reading SAML Response");
        String username = "";
        String email = "";
        MoSAMLPluginSettings settings = getMoSAMLPluginSettings();
        MoSAMLResponse MoSAMLResponse ;
        MoSAMLManager moSAMLManager = new MoSAMLManager(getMoSAMLPluginSettings());
        MoSAMLTemplateManager moSAMLTemplateManager = new MoSAMLTemplateManager(getMoSAMLPluginSettings());

        try {
            MoSAMLResponse = moSAMLManager.readSAMLResponse(request, response,settings);

            if (StringUtils.contains(relayState, "testidpconfiguration")) {
                LOGGER.fine("Showing Test Configuration Result");
                moSAMLTemplateManager.showTestConfigurationResult(MoSAMLResponse, request, response, null);
                return null;
            }
            LOGGER.fine("Not showing test config");

            if (MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute()) != null
                    && MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute()).length == 1) {
                username = MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute())[0];
                username = loadUserName(username);
            }

            if (MoSAMLResponse.getAttributes().get(settings.getEmailAttribute()) != null
                    && MoSAMLResponse.getAttributes().get(settings.getEmailAttribute()).length == 1) {
                email = MoSAMLResponse.getAttributes().get(settings.getEmailAttribute())[0];
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
                    User newUser = userCreateSAML( username, email, settings, MoSAMLResponse);
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
                ArrayList<String> usernameList = handleEmailLogin(request, response, email, settings, MoSAMLResponse);
                if(usernameList.size() > 1){
                    LOGGER.fine("Multiple Mail Addresses");
                    String errorMessage = "<div class=\"alert alert-danger\">More than one user found with this email address.</div><br>";
                    return doMoLogin(request,response,errorMessage);}
                if (usernameList.size()==0 && !settings.getUserCreate()) {
                    LOGGER.fine("User does not exist and user creation is disabled");
                    String errorMessage = "<div class=\"alert alert-danger\">User does not Exist</div><br>";
                    return doMoLogin(request, response, errorMessage);
                } else if (usernameList.size()==0 && settings.getUserCreate()) {
                    User newUser = userCreateSAML(username, email, settings, MoSAMLResponse);
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

        } catch (Exception ex) {
            LOGGER.fine("Invalid response");
            String errorMessage = "<div class=\"alert alert-danger\">Error occurred while reading response.</div><br>";
            return doMoLogin(request, response, errorMessage);

        }

    }

    private ArrayList<String> handleEmailLogin(StaplerRequest request, StaplerResponse response, String email, MoSAMLPluginSettings settings, MoSAMLResponse moSAMLResponse) {
        ArrayList<String> usernameList= new ArrayList<String>();
        try {
            Collection<User> users = User.getAll();

            for (User user : users) {
                String emailAddress = user.getProperty(Mailer.UserProperty.class).getAddress();
                if (emailAddress.equals(email)) {
                    usernameList.add(user.getId());
                }
            }

        } catch (Exception e) {
            LOGGER.fine("Error Occurred while searching for user");
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
                String value = responseSAMLAttributes.get(name).toString();
                System.out.println(key + " " + value);
            }
           /* for (String name: getSamlCustomAttributes.keySet()){
                String key = name.toString();
                String value = responseSAMLAttributes.get(name).toString();
                System.out.println(key + " " + value);
            }*/

            for (MoAttributeEntry attributeEntry : getSamlCustomAttributes()) {
                LOGGER.fine("attributeEntry"+attributeEntry);
                if (attributeEntry instanceof MoAttribute) {
                    MoAttribute attr = (MoAttribute) attributeEntry;

                    MoSAMLuserProperty.Attribute item = new MoSAMLuserProperty.Attribute(attr.getName(), attr.getDisplayName());
                    LOGGER.fine(attr.getName()+ attr.getDisplayName()+"sssS");
                    if (responseSAMLAttributes.containsKey(attr.getName())) {
                        // LOGGER.fine("in there");
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
                LOGGER.fine("Error Occured while updating attributes" + e);
            }
        }
    }


    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(authentication -> {
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

            UserDetails details = user.getUserDetailsForImpersonation();
            LOGGER.fine("UserDetails"+details);

            GrantedAuthority[] authorities= details.getAuthorities();
            List<GrantedAuthority>authorityList= new ArrayList<>();
            for (GrantedAuthority authority : authorities) {

                authorityList.add(authority);
            }
            MoSAMLUserInfo userInfo = new MoSAMLUserInfo(user.getId(), authorityList.toArray(new GrantedAuthority[authorityList.size()]));
            MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
            SecurityContextHolder.getContext().setAuthentication(tokenInfo);
            SecurityListener.fireAuthenticated(userInfo);
            SecurityListener.fireLoggedIn(user.getId());
           return HttpResponses.redirectTo(redirectUrl);

        } else {
            LOGGER.fine("User does not exist.");
            String errorMessage = "<div class=\"alert alert-danger\">User does not exist..</div><br>";
            return doMoLogin(request,response,errorMessage);
        }
    }

    public String getMetadataUrl() {
        return metadataUrl;
    }

    public String getMetadataFilePath() {
        return metadataFilePath;
    }
    public String getIdpEntityId() {
        return idpEntityId;
    }
    
    public String getSsoUrl() {
        return ssoUrl;
    }

    public String getPublicx509Certificate() {
        return publicx509Certificate;
    }

    public String getUsernameAttribute() {
        if (StringUtils.isEmpty(usernameAttribute)) {
            return "NameID";
        } else {
            return usernameAttribute;
        }
    }

    public String getEmailAttribute() {
        if (StringUtils.isEmpty(emailAttribute)) {
            return "NameID";
        } else {
            return emailAttribute;
        }
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


    

    public String getNameIDFormat() {
        return nameIDFormat;
    }

    public Boolean getSignedRequest() {
        return BooleanUtils.toBooleanDefaultIfNull(signedRequest, true);
    }

    public Boolean getSplitnameAttribute() {
        return BooleanUtils.toBooleanDefaultIfNull(splitnameAttribute, false);
    }
    public Boolean getUserCreate() {
        return userCreate;
    }

    public Boolean getForceAuthn(){ return forceAuthn; }
    public String getSslUrl() {
        return sslUrl;
    }

    public String getLoginType() {
        return loginType;
    }

    public String getRegexPattern() {
        return regexPattern;
    }

    public Boolean getEnableRegexPattern() {
        return enableRegexPattern;
    }

    public String getSsoBindingType() {
        return ssoBindingType;
    }

    public String getSloBindingType() {
        return sloBindingType;
    }


    public String getsPEntityID() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getAudienceURI() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getAcsURL() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL+"/securityRealm/moSamlAuth";
    }

    public String getSpLogoutURL() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL+"/securityRealm/logout";
    }
    public String getBackdoorURL() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL+"/securityRealm/moLoginAction";
    }

    public String getUsernameCaseConversion() {
        return usernameCaseConversion;
    }
    public String getFullnameAttribute() {
        return fullnameAttribute;
    }

    public Boolean getUserAttributeUpdate() {
        return userAttributeUpdate;
    }

    public String getNewUserGroup() {
        return newUserGroup;
    }

    public void setNewUserGroup(String newUserGroup) {
        this.newUserGroup = newUserGroup;
    }

    public String getAuthnContextClass() {
        return authnContextClass;
    }

    public void setAuthnContextClass(String authnContextClass) {
        this.authnContextClass = authnContextClass;
    }

    @NonNull
    public List<MoAttributeEntry> getSamlCustomAttributes() {
        if (samlCustomAttributes == null) {
            return java.util.Collections.emptyList();
        }
        return samlCustomAttributes;
    }

    public void setSamlCustomAttribute(List<MoAttributeEntry> samlCustomAttributes) {
        this.samlCustomAttributes = samlCustomAttributes;
    }


    private MoSAMLPluginSettings getMoSAMLPluginSettings() {
        MoSAMLPluginSettings settings = new MoSAMLPluginSettings(idpEntityId, ssoUrl, metadataUrl,
                metadataFilePath, publicx509Certificate, usernameCaseConversion, usernameAttribute, emailAttribute, nameIDFormat,
                sslUrl, loginType, regexPattern, enableRegexPattern, signedRequest, userCreate, forceAuthn, ssoBindingType, sloBindingType, fullnameAttribute, samlCustomAttributes, userAttributeUpdate,
                newUserGroup,authnContextClass);
        return settings;
    }

    private MoSAMLManager getMoSAMLManager() {
        MoSAMLManager moSAMLManager = new MoSAMLManager(getMoSAMLPluginSettings());
        return moSAMLManager;
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


        public FormValidation doCheckIdpEntityId(@QueryParameter String idpEntityId) {
            if (StringUtils.isEmpty(idpEntityId)) {
                return FormValidation.error("The Entity ID Can not be kept blank.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckSsoUrl(@QueryParameter String ssoUrl) {
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

        public FormValidation doCheckUsernameAttribute(@QueryParameter String usernameAttribute, @QueryParameter String loginType) {
            if (StringUtils.isEmpty(usernameAttribute) && loginType.equals("usernameLogin")) {
                return FormValidation.warning("Username Can not kept blank");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckEmailAttribute(@QueryParameter String emailAttribute, @QueryParameter String loginType) {
            if (StringUtils.isEmpty(emailAttribute) && loginType.equals("emailLogin")) {
                return FormValidation.warning("Email Address Can not kept blank");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckX509Certificate(@QueryParameter String publicx509Certificate) {
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


        public FormValidation doCheckRegexPattern(@QueryParameter Boolean enableRegexPattern, @QueryParameter String regexPattern) {

            if (enableRegexPattern && StringUtils.isEmpty(regexPattern)) {
                return FormValidation.error("The Regex Pattern is not Valid");
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doUserCreate(@QueryParameter Boolean userCreate, @QueryParameter String emailAttribute, @QueryParameter String usernameAttribute) {

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

        public FormValidation doCheckUserAttributeUpdate(@QueryParameter Boolean userAttributeUpdate) {
            if (! userAttributeUpdate) {
                return FormValidation.warning("Available in premium version");
            }
            return FormValidation.ok();
        }
        public FormValidation doCheckSignedRequest(@QueryParameter Boolean signedRequest) {
            if (! signedRequest) {
                return FormValidation.warning("Available in premium version");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckSplitnameAttribute(@QueryParameter Boolean splitnameAttribute) {
                return FormValidation.warning("Available in premium version");
        }
        public FormValidation doCheckDisableDefaultLogin(@QueryParameter Boolean disableDefaultLogin) {
            if (! disableDefaultLogin) {
                return FormValidation.warning("Available in premium version");
            }
            return FormValidation.ok();
        }


        public FormValidation doSupportEmail(@QueryParameter("supportEmail") final String supportEmail) {

            if (!isValidEmailAddress(supportEmail)) {
                LOGGER.fine("Invalid Support Email");
                return FormValidation.error("Please enter valid mail Address.");
            } else if(StringUtils.isEmpty(supportEmail)) {
                return FormValidation.error("Please enter mail Address.");
            }else {
                return FormValidation.ok();
            }
        }

            public FormValidation doSendSupportMail(@QueryParameter("supportEmail") final String supportEmail,
                                                @QueryParameter("supportName") final String supportName,
                                                @QueryParameter("supportQuery") final String supportQuery
                                                ) {


            if (StringUtils.isEmpty(supportEmail)) {
                LOGGER.fine("Empty Support Email");
                return FormValidation.error("Please enter contact mail Address.");

            } else if (StringUtils.isEmpty(supportQuery)) {
                LOGGER.fine("Empty Support Query");
                return FormValidation.error("Please enter Query.");

            } else if (!StringUtils.isEmpty(supportEmail)&&!isValidEmailAddress(supportEmail)) {
                LOGGER.fine("Invalid Support Email");

                return FormValidation.error("Please enter valid mail Address.");
            } else {
                try {
                    LOGGER.fine("Valid Email Address and sending query.");

                    LOGGER.fine("Received Query - reason:" + supportQuery +
                            ",contact_email:" + supportEmail + ",Name: "+supportName );
                    //supportEmail = StringUtils.defaultIfEmpty(supportEmail, StringUtils.EMPTY);
                    LOGGER.fine("Sending Query - reason:" + supportQuery +",contact_email:" + supportEmail+ "");
                    String content=new String();
                    content = content + "Hello,<br><br>Email: " + supportEmail + "<br><br>Name: "+supportName+
                            "<br><br>Plugin Name: " +"Jenkins SAML SSO" ;
                    content = content + "<br><br>Query Details: "+supportQuery ;
                    content = content + "<br><br>Thanks<br>Jenkins Admin";
                    JSONObject jsonObject = new JSONObject();
                    jsonObject.put("customerKey", MoSAMLAddIdp.DEFAULT_CUSTOMER_KEY);
                    jsonObject.put("sendEmail", true);
                    JSONObject emailObject = new JSONObject();
                    emailObject.put("customerKey", MoSAMLAddIdp.DEFAULT_CUSTOMER_KEY);
                    emailObject.put("fromEmail", "no-reply@xecurify.com");
                    emailObject.put("bccEmail", "no-reply@xecurify.com");
                    emailObject.put("fromName", "miniOrange");
                    emailObject.put("toEmail", "info@xecurify.com");
                    emailObject.put("toName", "info@xecurify.com");
                    emailObject.put("bccEmail", "info@xecurify.com");
                    emailObject.put("subject", "Feedback for " + "Jenkins SAML SSO");
                    emailObject.put("content", content);
                    jsonObject.put("email", emailObject);
                    String json = jsonObject.toString();
                    String response1 = MoHttpUtils.sendPostRequest(MoSAMLAddIdp.NOTIFY_API, json,
                            MoHttpUtils.CONTENT_TYPE_JSON, MoHttpUtils.getAuthorizationHeaders(Long.valueOf(MoSAMLAddIdp.DEFAULT_CUSTOMER_KEY),
                                    MoSAMLAddIdp.DEFAULT_API_KEY));
                    LOGGER.fine("Send_feedback response: " + response1);
                    return FormValidation.ok("Message Sent. The miniOrange support will contact soon.");
                } catch (Exception e) {
                    return FormValidation.error("Error occurred while sending request.");
                }
            }
        }
        public static boolean isValidEmailAddress(String email)
        {
            String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\."+
                    "[a-zA-Z0-9_+&*-]+)*@" +
                    "(?:[a-zA-Z0-9-]+\\.)+[a-z" +
                    "A-Z]{2,7}$";

            Pattern pat = Pattern.compile(emailRegex);
            if (email == null)
                return false;
            return pat.matcher(email).matches();
        }

        public FormValidation doPerformTestConfiguration(@QueryParameter String idpEntityId, @QueryParameter String ssoUrl, @QueryParameter String publicx509Certificate) {
            if(StringUtils.isEmpty(idpEntityId) || StringUtils.isEmpty(ssoUrl) || StringUtils.isEmpty(publicx509Certificate)) {
                LOGGER.fine("Entity ID is " +  "failed");
                return FormValidation.error("Save the idp configurations first. Could not perform test config");
            }
            LOGGER.fine("Test config called..");
            String testConfigUrl = getBaseUrl() + "/securityRealm/moSamlLogin?from=testidpconfiguration";
            return FormValidation.okWithMarkup("Click " + "<a href='"+ testConfigUrl+ "' target='_blank' >here</a>"+ " to see the test configurations result.");
        }

        public FormValidation doValidateMetadataUrl(@QueryParameter String metadataUrl) throws Exception {
            String metadata = sendGetRequest(metadataUrl);
            try{
                List<String> metadataUrlValues = configureFromMetadata(metadata);
            }catch (Exception e){
                LOGGER.fine("Invalid metadata Url" + e);
                return FormValidation.error("Invalid metadata Url");
            }
            return FormValidation.okWithMarkup("Valid metadata Url, please hit save button");
        }
        public FormValidation doValidateMetadataFile(@QueryParameter String metadataFilePath) throws Exception {
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
    private String loadUserName(String username) {
        MoSAMLPluginSettings settings = getMoSAMLPluginSettings();
        if ("lowercase".compareTo(settings.getUsernameCaseConversion()) == 0) {
            username = username.toLowerCase();
        } else if ("uppercase".compareTo(settings.getUsernameCaseConversion()) == 0) {
            username = username.toUpperCase();
        }
        return username;
    }

}
