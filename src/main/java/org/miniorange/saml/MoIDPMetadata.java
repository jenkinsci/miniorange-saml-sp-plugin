package org.miniorange.saml;


import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.parsers.DOMParser;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.credential.UsageType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MoIDPMetadata {

    private static Log LOGGER = LogFactory.getLog(MoIDPMetadata.class);

    private String metadata;

    private EntityDescriptor entityDescriptor;
    public static String entityId;
    private Map<String, String> singleSignOnServices;
    private Map<String, String> singleLogoutServices;
    public static List<String> signingCertificates;
    public static String certificate;
    public static String nameIdFormat;

    public MoIDPMetadata(String metadata) {
        try {
            if (StringUtils.isNotBlank(metadata) && metadata.trim().startsWith("<") && metadata.trim().endsWith(">")) {
                this.metadata = StringUtils.trimToEmpty(metadata);
                MoSAMLUtils.doBootstrap();
                DOMParser parser = new DOMParser();
                parser.parse(new InputSource(new StringReader(this.metadata)));
                Document document = parser.getDocument();
                Element element = document.getDocumentElement();
                UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
                Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
                XMLObject xmlObj = unmarshaller.unmarshall(element);
                entityDescriptor = (EntityDescriptor) xmlObj;
                IDPSSODescriptor idpssoDescriptor = entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

                if (idpssoDescriptor != null) {
                    entityId = entityDescriptor.getEntityID();
                    LOGGER.debug("EntityID: " + entityId);
                    singleSignOnServices = new HashMap<>();
                    for (SingleSignOnService ssoService : idpssoDescriptor.getSingleSignOnServices()) {
                        String binding = ssoService.getBinding();
                        String location = ssoService.getLocation();

                        if (StringUtils.equals(binding, SAMLConstants.SAML2_REDIRECT_BINDING_URI) || StringUtils
                                .equals(binding, SAMLConstants.SAML2_POST_BINDING_URI)) {
                            LOGGER.debug("SingleSignOnService Binding: " + binding + ", Location: " + location);
                            singleSignOnServices.put(binding, location);
                        }
                    }

                    singleLogoutServices = new HashMap<>();
                    for (SingleLogoutService sloService : idpssoDescriptor.getSingleLogoutServices()) {
                        String binding = sloService.getBinding();
                        String location = sloService.getLocation();
                        if (StringUtils.equals(binding, SAMLConstants.SAML2_REDIRECT_BINDING_URI) || StringUtils
                                .equals(binding, SAMLConstants.SAML2_POST_BINDING_URI)) {
                            LOGGER.debug("SingleLogoutService Binding: " + binding + ", Location: " + location);
                            singleLogoutServices.put(binding, location);
                        }
                    }

                    if(!idpssoDescriptor.getNameIDFormats().isEmpty()) {
                        nameIdFormat = StringUtils.defaultIfBlank(idpssoDescriptor.getNameIDFormats().get(0).getFormat(),
                                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                    } else {
                        nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
                    }
                    signingCertificates = new ArrayList<>();
                    for (KeyDescriptor key : idpssoDescriptor.getKeyDescriptors()) {
                        certificate = null;
                        if (key.getKeyInfo().getX509Datas().size() > 0
                                && key.getKeyInfo().getX509Datas().get(0).getX509Certificates().size() > 0) {
                            certificate = key.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0)
                                    .getValue();
                        }
                        if (StringUtils.isBlank(certificate)) {
                            break;
                        }
                        if (UsageType.UNSPECIFIED.equals(key.getUse())) {
//                            LOGGER.debug("Certificate UsageType: " + key.getUse() + ", Certificate: " + certificate);
                            if(MoSAMLUtils.isValidPublicCertificate(certificate))
                                signingCertificates.add(certificate);
                        }
                        if (UsageType.SIGNING.equals(key.getUse())) {
//                            LOGGER.debug("Certificate UsageType: " + key.getUse() + ", Location: " + certificate);
                            if(MoSAMLUtils.isValidPublicCertificate(certificate))
                                signingCertificates.add(certificate);
                        }
                    }
                    if (StringUtils.isNotBlank(entityId) && singleSignOnServices.size() > 0 && !signingCertificates.isEmpty()) {
                        return;
                    }
                }
            }
        } catch (Throwable t) {
            return ;
//            LOGGER.error(MoPluginException.PluginErrorCode.METADATA_PARSE.getMessage(), t);
//            throw new MoPluginException(MoPluginException.PluginErrorCode.METADATA_PARSE, t.getMessage(), t);
        }
        // Throw exception. Not a valid metadata.
//        throw new MoPluginException(MoPluginException.PluginErrorCode.METADATA_PARSE, MoPluginException
//                .PluginErrorCode.METADATA_PARSE.getMessage());
    }

    public EntityDescriptor getEntityDescriptor() {
        return entityDescriptor;
    }

    public void setEntityDescriptor(EntityDescriptor entityDescriptor) {
        this.entityDescriptor = entityDescriptor;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public Map<String, String> getSingleSignOnServices() {
        return singleSignOnServices;
    }

    public void setSingleSignOnServices(Map<String, String> singleSignOnServices) {
        this.singleSignOnServices = singleSignOnServices;
    }

    public Map<String, String> getSingleLogoutServices() {
        return singleLogoutServices;
    }

    public void setSingleLogoutServices(Map<String, String> singleLogoutServices) {
        this.singleLogoutServices = singleLogoutServices;
    }

    public List<String> getSigningCertificates() {
        return signingCertificates;
    }

    public void setSigningCertificates(List<String> signingCertificates) {
        this.signingCertificates = signingCertificates;
    }

    public static String getCertificate() {
        return certificate;
    }

    public static void setCertificate(String certificate) {
        MoIDPMetadata.certificate = certificate;
    }

    public static String getNameIdFormat() {
        return nameIdFormat;
    }

    public static void setNameIdFormat(String nameIdFormat) {
        MoIDPMetadata.nameIdFormat = nameIdFormat;
    }
}
