package org.miniorange.saml;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;

import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;

import org.opensaml.saml2.core.*;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.validation.ValidationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.io.UnsupportedEncodingException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import java.util.logging.Logger;

public class MoSAMLManager {

        private MoSAMLPluginSettings settings;
        private String certificateexpected="";
    private static final Logger LOGGER = Logger.getLogger(MoSAMLManager.class.getName());

	public MoSAMLManager(MoSAMLPluginSettings settings) {
        this.settings = settings;
    }

        public MoSAMLResponse readSAMLResponse(HttpServletRequest request, HttpServletResponse response, MoSAMLPluginSettings settings) {
        try {

            MoSAMLUtils.doBootstrap();
            String encodedSAMLResponse = request.getParameter(MoSAMLUtils.SAML_RESPONSE_PARAM);
            Response samlResponse = MoSAMLUtils.decodeResponse(encodedSAMLResponse);
            if (!StringUtils.equals(samlResponse.getStatus().getStatusCode().getValue(), StatusCode.SUCCESS_URI)) {
                LOGGER.fine("Invalid SAML response. SAML Status Code received: "
                       + samlResponse.getStatus().getStatusCode().getValue());
                String message = StringUtils.EMPTY;
                if (samlResponse.getStatus().getStatusMessage() != null) {
                   LOGGER.fine("Saml Status Message received: "
                           + samlResponse.getStatus().getStatusMessage().getMessage());
                    message = samlResponse.getStatus().getStatusMessage().getMessage()
                            + ". Status Code received in SAML response: "
                            + samlResponse.getStatus().getStatusCode().getValue().split(":")[7];
                } else {
                    message = "Invalid status code \""
                            + samlResponse.getStatus().getStatusCode().getValue().split(":")[7]
                            + "\" received in SAML response";
                }

                if(StringUtils.equalsIgnoreCase(samlResponse.getStatus().getStatusCode().getValue().split(":")[7], StatusCode.RESPONDER_URI)){
                    LOGGER.fine(message);
                    throw new MoSAMLException(message, MoSAMLException.SAMLErrorCode.RESPONDER);
                }else{
                    LOGGER.fine(message);
                    throw new MoSAMLException(message, MoSAMLException.SAMLErrorCode.INVALID_SAML_STATUS);
                }
            }
            Assertion assertion;
            if (samlResponse.getAssertions() != null && samlResponse.getAssertions().size() > 0) {
                assertion = samlResponse.getAssertions().get(0);
            } else {
                assertion = MoSAMLUtils.decryptAssertion(samlResponse.getEncryptedAssertions().get(0),
                        settings.getPublicSPCertificate(), settings.getPrivateSPCertificate());
            }
            LOGGER.fine(String.valueOf(assertion));

            verifyConditions(assertion, settings.getSPAudienceURI());

            String acs = settings.getSpAcsUrl();
            verifyIssuer(samlResponse, assertion, settings.getIdpEntityId());
            verifyDestination(samlResponse, acs);
            verifyRecipient(assertion, acs);
            MoSAMLException t = null;
            Boolean verified = Boolean.FALSE;
            try {
                verified = verifyCertificate(samlResponse, assertion, settings.getX509PublicCertificate());
                LOGGER.fine("Verified Certificates:"+verified);
            } catch (MoSAMLException e) {
                t = e;
            }

            if (!verified) {
                LOGGER.fine(t.getMessage());
                throw t;
            }
            Map<String, String[]> attributes = getAttributes(assertion);
            NameID nameId = assertion.getSubject().getNameID();
            String nameIdValue = StringUtils.EMPTY;
            String sessionIndex = assertion.getAuthnStatements().get(0).getSessionIndex();
            if (nameId != null) {
                nameIdValue = nameId.getValue();
            }
            attributes.put("NameID", new String[] { nameIdValue });
            MoSAMLResponse samlResponseObj = new MoSAMLResponse(attributes, nameIdValue, sessionIndex);
            return samlResponseObj;
        } catch (MoSAMLException e) {
            LOGGER.fine(e.getMessage());
            throw e;
        } catch (Throwable e) {
            LOGGER.fine("An error occurred while verifying the SAML Response.");
            throw new MoSAMLException(e, MoSAMLException.SAMLErrorCode.UNKNOWN);
        }
    }

        private void verifyIssuer(Response response, Assertion assertion, String idpEntityId) {
        LOGGER.fine("Verifying Issuer in SAML Response");
        String issuerInResponse = response.getIssuer().getValue();
        String issuerInAssertion = assertion.getIssuer().getValue();
        if (!StringUtils.equals(issuerInResponse, idpEntityId)) {
            MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_ISSUER;
            MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
                    buildResolutionMessage(errorCode, idpEntityId, issuerInResponse), errorCode);
            LOGGER.fine(e.getMessage());
            throw e;
        }
        if (!StringUtils.equals(issuerInAssertion, idpEntityId)) {
            MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_ISSUER;
            MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
                    buildResolutionMessage(errorCode, idpEntityId, issuerInAssertion), errorCode);
            LOGGER.fine(e.getMessage());
            throw e;
        }
    }

        private void verifyDestination(Response response, String acsUrl) {
        // Destination is Optional field so verify only if exist.
        LOGGER.fine("Verifying Destination if present in SAML Response");
        String destInResponse = response.getDestination();
        LOGGER.fine("destInResponse: "+destInResponse+"acsURL: "+acsUrl);

        if (StringUtils.isBlank(destInResponse) || StringUtils.equals(destInResponse, acsUrl)) {
            return;
        }
        MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_DESTINATION;
        MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
                buildResolutionMessage(errorCode, acsUrl, destInResponse), errorCode);
        LOGGER.fine(e.getMessage());
        throw e;
    }

        private void verifyRecipient(Assertion assertion, String acsUrl) {
        LOGGER.fine("Verifying Recipient if present in SAML Response");

        String recipientInResponse = assertion.getSubject().getSubjectConfirmations().get(0)
                .getSubjectConfirmationData().getRecipient();
            LOGGER.fine("destInResponse: "+recipientInResponse);
        if (StringUtils.isBlank(recipientInResponse) || StringUtils.equals(recipientInResponse, acsUrl) ) {
            return;
        }
        MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_RECIPIENT;
        MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
                buildResolutionMessage(errorCode, acsUrl, recipientInResponse), errorCode);
        LOGGER.fine(e.getMessage());
        throw e;
    }



        private void verifyConditions(Assertion assertion, String audienceExpected) {
        LOGGER.fine("Verifying Conditions...");
        Date now = new DateTime().toDate();
        Date notBefore = null;
        Date notOnOrAfter = null;
        long timeDifferenceInBefore = 0;
        long timeDifferenceInAfter = 0;
        if (assertion.getConditions().getNotBefore() != null) {
            LOGGER.fine("Verifying Conditions...");
            notBefore = assertion.getConditions().getNotBefore().toDate();
            if (now.before(notBefore))
                timeDifferenceInBefore = Math.abs(notBefore.getTime() - now.getTime());
            LOGGER.fine("timeDifferenceInBefore = " + timeDifferenceInBefore);
        }
        if (assertion.getConditions().getNotOnOrAfter() != null) {
            LOGGER.fine("Verifying Conditions...");
            notOnOrAfter = assertion.getConditions().getNotOnOrAfter().toDate();
            if (now.after(notOnOrAfter))
                timeDifferenceInAfter = Math.abs(now.getTime() - notOnOrAfter.getTime());
            LOGGER.fine("timeDifferenceNotOnOrAfter = " + timeDifferenceInAfter);
        }
            LOGGER.fine("audienceExpected Before: "+audienceExpected);
        if(audienceExpected.endsWith("/")){
            audienceExpected= audienceExpected.substring(0,audienceExpected.length()-1);
        }
        LOGGER.fine("audienceExpected After : "+audienceExpected);
        List<Audience> audiencesInAssertion = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences();

        for (Audience audience : audiencesInAssertion) {
            if (StringUtils.equalsIgnoreCase(audience.getAudienceURI(), audienceExpected)) {
                return;
            }
        }

        MoSAMLException e = new MoSAMLException(MoSAMLException.SAMLErrorCode.INVALID_AUDIENCE);
        LOGGER.fine(MoSAMLException.SAMLErrorCode.INVALID_AUDIENCE.getMessage());
        throw e;
    }



        private Boolean verifyCertificate(Response response, Assertion assertion, String x509Certificate) {
        LOGGER.fine("Verifying Certificates.");
        if(x509Certificate!=null)
            try {
                if (!response.isSigned() && !assertion.isSigned()) {
                    MoSAMLException e = new MoSAMLException(MoSAMLException.SAMLErrorCode.ASSERTION_NOT_SIGNED);
                    LOGGER.fine(MoSAMLException.SAMLErrorCode.ASSERTION_NOT_SIGNED.getMessage());
                    throw e;
                }
                if (response.isSigned()) {
                    return MoSAMLUtils.verifyCertificate(response, x509Certificate);
                }
                if (assertion.isSigned()) {
                    return MoSAMLUtils.verifyCertificate(assertion, x509Certificate);
                }
                LOGGER.fine("Error occurred while verifying the certificate");
            } catch (CertificateException e) {
                MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_CERTIFICATE;
                MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
                        buildResolutionforcertificate(errorCode,assertion,response), errorCode);

                LOGGER.fine(samlexception.getMessage());
                throw samlexception;
            } catch (ValidationException e) {
                MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_SIGNATURE;
                MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
                        buildResolutionforcertificate(errorCode,assertion,response), errorCode);

                LOGGER.fine(samlexception.getMessage());
                throw samlexception;
            } catch (NoSuchAlgorithmException e) {
                MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_CERTIFICATE;
                MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
                        buildResolutionforcertificate(errorCode,assertion,response), errorCode);

                LOGGER.fine(samlexception.getMessage());
                throw samlexception;
            } catch (InvalidKeySpecException e) {
                MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_CERTIFICATE;
                MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
                        buildResolutionforcertificate(errorCode,assertion,response), errorCode);

                LOGGER.fine(samlexception.getMessage());
                throw samlexception;
            }
        return false;
    }



        private String buildResolutionforcertificate(MoSAMLException.SAMLErrorCode error,Assertion assertion,Response response)
        {
            try {
                if (assertion.isSigned()) {
                    List<X509Data> x509Datas = assertion.getSignature().getKeyInfo().getX509Datas();
                    for (X509Data x509Data : x509Datas) {
                        List<X509Certificate> certificates = x509Data.getX509Certificates();

                        for (X509Certificate certificate : certificates) {
                            certificateexpected = certificate.getValue();

                        }
                    }
                } else if (response.isSigned()) {
                    List<X509Data> x509Datas = response.getSignature().getKeyInfo().getX509Datas();
                    for (X509Data x509Data : x509Datas) {
                        List<X509Certificate> certificates = x509Data.getX509Certificates();

                        for (X509Certificate certificate : certificates) {
                            certificateexpected = certificate.getValue();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                LOGGER.fine(e.getMessage());

            }
            StringBuffer errorMsg = new StringBuffer(error.getResolution());
            errorMsg.append(" Expected certificate : ");
            errorMsg.append(
                    "<textarea rows='6' cols='100' word-wrap='break-word;' style='width:580px; margin:0px; " +
                            "height:290px;' id ='errormsg' readonly>-----BEGIN CERTIFICATE-----"+ certificateexpected + "-----END CERTIFICATE-----</textarea> ");
            errorMsg.append(
                    "<div style=\"margin:3%;display:block;text-align:center;\"><input id =\"copy-button\" style=\"padding:1%;"
                            + "width:150px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;"
                            + "border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;"
                            + "box-sizing:border-box;border-color: #0073AA;box-shadow:0px 1px 0px rgba(120,200,230,0.6) inset;"
                            + "color: #FFF;\" type=\"button\" value=\"Copy to Clipboard\"></div>");
            errorMsg.append("<script>" + "document.querySelector(\"#copy-button\").onclick = function() {"
                    + "document.querySelector(\"#errormsg\").select();" + "document.execCommand('copy');" + "};"
                    + "</script>");

            return errorMsg.toString();
        }

        private Map<String, String[]> getAttributes(Assertion assertion) {
        LOGGER.fine("Getting attributes from SAML Response");
        Map<String, String[]> attributes = new HashMap<String, String[]>();
        if (assertion.getAttributeStatements().size() > 0) {
            for (Attribute attr : assertion.getAttributeStatements().get(0).getAttributes()) {
                if (attr.getAttributeValues().size() > 0) {
                    String[] values = new String[attr.getAttributeValues().size()];
                    for (int i = 0; i < attr.getAttributeValues().size(); i++) {
                        values[i] = attr.getAttributeValues().get(i).getDOM().getTextContent();
                    }
                    attributes.put(attr.getName(), values);
                }
            }
        }
        return attributes;
    }




        private String buildResolutionMessage(MoSAMLException.SAMLErrorCode error, String found, String expected) {
        StringBuffer errorMsg = new StringBuffer(error.getResolution());
        errorMsg.append(" app was expecting ");
        errorMsg.append(expected);
        errorMsg.append(" but found: ");
        errorMsg.append(found);
        return errorMsg.toString();
    }
   public void createAuthnRequestAndRedirect(HttpServletRequest request, HttpServletResponse response, String relayState,MoSAMLPluginSettings settings) {
       try {
           LOGGER.fine("Creating Authentication Request and rediecting user to Idp for authentication");
           MoSAMLUtils.doBootstrap();
           relayState=StringUtils.substringAfter(relayState,"from=");
           AuthnRequest authnRequest = MoSAMLUtils.buildAuthnRequest(settings.getSPEntityID(),
                   settings.getSpAcsUrl(), settings.getSsoUrl(), settings.getNameIDFormat(), BooleanUtils.toBooleanDefaultIfNull(settings.getForceAuthn(),false),StringUtils.defaultString(settings.getAuthnContextClass(),"None"));
           if (StringUtils.equals(settings.getSsoBindingType(), "HttpPost")) {
               response.setContentType("text/html");
               LOGGER.fine("HTTP-POST Binding selected for SSO");
               if (settings.getSignedRequest()) {
                   authnRequest = (AuthnRequest) MoSAMLUtils.signHttpPostRequest(authnRequest,
                           settings.getPublicSPCertificate(), settings.getPrivateSPCertificate());
               }
               String encodedAuthnRequest = MoSAMLUtils.base64EncodeRequest(authnRequest, true);
               String form = createHttpPostRequestForm(settings.getSsoUrl(), encodedAuthnRequest, relayState);
               LOGGER.fine("form created for post is " + form);
               response.getOutputStream().write(form.getBytes());
               response.getOutputStream().close();
               return;
           } else {
               LOGGER.fine("HTTP-Redirect Binding selected for SSO");
               String encodedAuthnRequest = MoSAMLUtils.base64EncodeRequest(authnRequest, false);
               LOGGER.fine("encodedAuthnRequest: "+encodedAuthnRequest);
               String urlForSignature = createRequestQueryParamsForSignature(encodedAuthnRequest,relayState);
               String signature = MoSAMLUtils.signHttpRedirectRequest(urlForSignature,
                       XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, settings.getPublicSPCertificate(),
                       settings.getPrivateSPCertificate());
               String redirectUrl = StringUtils.EMPTY;
               if (settings.getSignedRequest()) {
                   redirectUrl = createRedirectURL(settings.getSsoUrl(),encodedAuthnRequest, relayState ,
                           XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, signature, false);
               } else {
                   LOGGER.fine("sending relay state " + relayState);
                   redirectUrl = createUnSignedRedirectURL(settings.getSsoUrl(), encodedAuthnRequest,
                            relayState,false);

               }
               httpRedirect(response, redirectUrl);
               // response.sendRedirect(redirectUrl);
           }
       } catch (Throwable t) {
           LOGGER.fine("An unknown error occurred while creating the AuthnRequest."+ t);
           throw new MoSAMLException(MoSAMLException.SAMLErrorCode.UNKNOWN);
       }
   }
    private String createHttpPostRequestForm(String ssoUrl, String encodedRequest, String relayState) {
        String form =   "<html>\n" +
                        "<head>\n" +
                        "    <script>\n" +
                        "        initiate();\n" +
                        "        function initiate() {\n" +
                        "            var form = document.getElementById('saml-request-form');\n" +
                        "            if(form){\n" +
                        "                form.submit();\n" +
                        "            }else{\n" +
                        "                setTimeout(initiate,50)\n" +
                        "            }\n" +
                        "        }\n" +
                        "    </script>\n" +
                        "    </head>\n" +
                        "\n" +
                        "<body>Please wait...\n" +
                        "<form action= \"" + ssoUrl + "\"  method=\"post\" id=\"saml-request-form\">\n" +
                        "<input type=\"hidden\" name=\"SAMLRequest\" value= \"" + encodedRequest + "\" />\n" +
                        "<input type=\"hidden\" name=\"RelayState\" value= \""+ relayState +"\"/>\n" +
                        "</form>\n" +
                        "</body>\n" +
                        "</html>";
        return form;
    }
    public static void httpRedirect(HttpServletResponse response, String redirectUrl) throws IOException {
        LOGGER.fine("Redirecting user to " + redirectUrl);
        response.sendRedirect(redirectUrl);
    }

   private String createUnSignedRedirectURL(String url, String samlRequestOrResponse, String relayState,
                                            Boolean isResponse) throws UnsupportedEncodingException {
       StringBuilder builder = new StringBuilder(url);
       if (StringUtils.contains(url, "?") && !(StringUtils.endsWith(url, "?") || StringUtils.endsWith(url, "&"))) {
           builder.append("&");
       } else if (!StringUtils.contains(url, "?")) {
           builder.append("?");
       }
       if (isResponse) {
           builder.append(createResponseQueryParamsForSignature(samlRequestOrResponse, relayState));
       } else {
           builder.append(createRequestQueryParamsForSignature(samlRequestOrResponse, relayState));
       }
       return builder.toString();
   }
    private String createResponseQueryParamsForSignature(String httpRedirectResponse, String relayState)
            throws UnsupportedEncodingException {
        LOGGER.fine("Creating response query parameter for signature");
        StringBuffer urlForSignature = new StringBuffer();
        urlForSignature.append(MoSAMLUtils.SAML_RESPONSE_PARAM).append("=")
                .append(URLEncoder.encode(httpRedirectResponse, StandardCharsets.UTF_8.toString()));
        urlForSignature.append("&").append(MoSAMLUtils.RELAY_STATE_PARAM).append("="+relayState);
         {
            urlForSignature.append(URLEncoder.encode("/", StandardCharsets.UTF_8.toString()));
        }
        return urlForSignature.toString();
    }

    private String createRequestQueryParamsForSignature(String httpRedirectRequest, String relayState)
            throws UnsupportedEncodingException {
        LOGGER.fine("Creating request query parameter for signature");
        StringBuffer urlForSignature = new StringBuffer();
        //LOGGER.fine("encoded Authentication request: "+httpRedirectRequest);
        urlForSignature.append(MoSAMLUtils.SAML_REQUEST_PARAM).append("=")
                .append(URLEncoder.encode(httpRedirectRequest, StandardCharsets.UTF_8.toString()));
        urlForSignature.append("&").append(MoSAMLUtils.RELAY_STATE_PARAM).append("=");
        if (StringUtils.isNotBlank(relayState)) {
            LOGGER.fine("relay state is not blank "+ relayState);
            urlForSignature.append(URLEncoder.encode(relayState, StandardCharsets.UTF_8.toString()));
        } else {
            urlForSignature.append(URLEncoder.encode("/", StandardCharsets.UTF_8.toString()));
        }
        LOGGER.fine(urlForSignature.toString());
        return urlForSignature.toString();
    }



    private String createRedirectURL(String url, String samlRequestOrResponse, String relayState, String sigAlgo,
                                     String signature, Boolean isResponse) throws UnsupportedEncodingException {
        StringBuilder builder = new StringBuilder(url);
        if (StringUtils.contains(url, "?") && !(StringUtils.endsWith(url, "?") || StringUtils.endsWith(url, "&"))) {
            builder.append("&");
        } else if (!StringUtils.contains(url, "?")) {
            builder.append("?");
        }
        if (isResponse) {
            builder.append(createResponseQueryParamsForSignature(samlRequestOrResponse, relayState));
        } else {
            builder.append(createRequestQueryParamsForSignature(samlRequestOrResponse, relayState));
        }
        builder.append("&").append(MoSAMLUtils.SIGNATURE_ALGO_PARAM).append("=")
                .append(URLEncoder.encode(sigAlgo, "UTF-8")).append("&").append(MoSAMLUtils.SIGNATURE_PARAM).append("=")
                .append(URLEncoder.encode(signature, "UTF-8"));
        return builder.toString();
    }

}
