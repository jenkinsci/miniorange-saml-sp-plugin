package org.miniorange.saml;

public class MoSAMLException extends RuntimeException {
    private SAMLErrorCode errorCode;
    private String message;
    private String resolution;

    public MoSAMLException(SAMLErrorCode errorCode) {
        this.errorCode = errorCode;
        this.message = errorCode.getMessage();
        this.resolution = errorCode.getResolution();
    }

    public MoSAMLException(String message, String resolution, SAMLErrorCode errorCode) {
        this.errorCode = errorCode;
        this.message = message;
        this.resolution = resolution;
    }

    public MoSAMLException(Throwable cause, SAMLErrorCode errorCode) {
        super(cause);
        this.errorCode = errorCode;
        this.message = cause.getMessage();
        this.resolution = errorCode.getResolution();
    }

    public MoSAMLException(String message, SAMLErrorCode errorCode) {
        this.message = message;
        this.errorCode = errorCode;
        this.resolution = errorCode.getResolution();
    }

    @Override
    public String getMessage() {
        return message;
    }

    public String getResolution() { return resolution; }

    public SAMLErrorCode getErrorCode() {
        return errorCode;
    }

    public enum SAMLErrorCode {

        NOT_IN_TIMESTAMP("MO_ERROR_001", "Request has timed out or expired", "Please retry again"),
        INVALID_ISSUER("MO_ERROR_002", "Invalid Issuer in the SAML Response.", "Please verify IDP Entity ID value is correct."),
        INVALID_SIGNATURE("MO_ERROR_003", "Invalid Signature in the SAML Response. The certificate you provided did not match the signature in " +
                "SAML Response.", "Please verify the X.509 certificate is correct."),
        INVALID_DESTINATION("MO_ERROR_004", "Invalid Destination in the SAML Response.", "Make sure that Destination value is configured correctly on your IDP."),
        INVALID_RECIPIENT("MO_ERROR_005", "Invalid Recipient in the SAML Response.", "Make sure that Recipient value is configured correctly on your IDP."),
        INVALID_AUDIENCE("MO_ERROR_006", "Invalid Audience (SP Entity ID) in the SAML Response.", "Make sure that Audience value is configured correctly on your IDP."),
        INVALID_CERTIFICATE("MO_ERROR_007", "Invalid Certificate provided for validation. Incorrect certificate format.", "Please provide the correct X.509 Certificate."),
        RESPONSE_NOT_SIGNED("MO_ERROR_008", "SAML Response not signed by your IdP.", "Make sure your IDP is signing at least SAML Response or SAML Assertion."),
        ASSERTION_NOT_SIGNED("MO_ERROR_009", "SAML Assertion not signed by your IdP.", "Make sure your IDP is signing at least SAML Response or SAML Assertion."),
        UNKNOWN("MO_ERROR_010", "An unknown error occurred.", "Please check logs for the exact error and contact support for help."),
        INVALID_SAML_STATUS("MO_ERROR_011", "Invalid SAML Status code.", "The request could not be performed due to an error on the part of the SAML responder or SAML authority. Make sure IdP returns SUCCESS status code in SAML Response. Please unchecked the Send Signed Requests and try again"),
        RESPONDER("MO_ERROR_012", "Invalid SAML Status code.", "The request could not be performed due to an error on the part of the SAML responder or SAML authority. Make sure IdP returns SUCCESS status code in SAML Response. Please unchecked the Send Signed Requests in Configure IDP Tab and try again.");

        private String code;
        private String message;
        private String resolution;

        SAMLErrorCode(String code, String message, String resolution) {
            this.code = code;
            this.message = message;
            this.resolution = resolution;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        public String getResolution() {
            return resolution;
        }
    }

}

