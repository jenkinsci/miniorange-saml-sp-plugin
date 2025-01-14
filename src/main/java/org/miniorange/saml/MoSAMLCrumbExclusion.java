package org.miniorange.saml;

import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

@Extension
public class MoSAMLCrumbExclusion extends CrumbExclusion {
    private static final Logger LOGGER = Logger.getLogger(MoSAMLCrumbExclusion.class.getName());
    private static final String MO_JENKINS_LOGIN_ACTION = "/" + MoSAMLAddIdp.MO_JENKINS_LOGIN_ACTION;
    private static final String MO_JENKINS_SAML_LOGIN_ACTION = "/" + MoSAMLAddIdp.MO_JENKINS_SAML_LOGIN_ACTION;
    private static final String MO_SAML_SSO_FORCE_STOP = "/" + MoSAMLAddIdp.MO_SAML_SSO_FORCE_STOP;
    private static final String MO_SAML_SP_AUTH_URL = "/" + MoSAMLAddIdp.MO_SAML_SP_AUTH_URL;


    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String pathInfo = request.getPathInfo();
        if (ignoreCrumbCheck(pathInfo)) {
            filterChain.doFilter(request, response);
            return true;
        }
        return false;
    }

    private boolean ignoreCrumbCheck(String pathInfo) {
        if (pathInfo!=null && (pathInfo.equals(MO_JENKINS_LOGIN_ACTION) || pathInfo.equals(MO_JENKINS_LOGIN_ACTION + "/") || pathInfo.equals(MO_JENKINS_SAML_LOGIN_ACTION))) {
            return true;
        }
       else if (pathInfo!=null && (pathInfo.equals(MO_SAML_SSO_FORCE_STOP) || pathInfo.equals(MO_SAML_SSO_FORCE_STOP + "/"))) {
            return true;
        } else  if (pathInfo!=null && (pathInfo.equals(MO_SAML_SP_AUTH_URL) || pathInfo.equals(MO_SAML_SP_AUTH_URL + "/"))) {
            return true;
        }else {
            LOGGER.fine("Invalid Request");
            return false;
        }
    }
}
