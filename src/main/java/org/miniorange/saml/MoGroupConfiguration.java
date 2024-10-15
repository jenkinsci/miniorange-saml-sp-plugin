package org.miniorange.saml;

import hudson.model.RootAction;
import hudson.security.SecurityRealm;
import hudson.util.FormApply;

import hudson.util.Secret;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;


public class MoGroupConfiguration implements RootAction {

    private static final Logger LOGGER = Logger.getLogger(MoGroupConfiguration.class.getName());

    @Override
    public String getIconFileName() {
        return "symbol-people";
    }

    @Override
    public String getDisplayName() {
        return "GroupConfiguration";
    }

    @Override
    public String getUrlName() {
        return "GroupConfiguration";
    }

    @SuppressWarnings("unused")
    @edu.umd.cs.findbugs.annotations.CheckForNull
    public SecurityRealm getRealm() {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        if (realm instanceof MoSAMLAddIdp) {
            return realm;
        } else {
            return null;
        }
    }

    @RequirePOST
    @Restricted(NoExternalUse.class)
    public void doSaveConfiguration(StaplerRequest request, StaplerResponse response)
            throws ServletException, IOException {
        try {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            JSONObject json = request.getSubmittedForm();
            MoSAMLAddIdp currentConfiguration = (MoSAMLAddIdp) Jenkins.get().getSecurityRealm();

            currentConfiguration.setCrowdURL(json.getString("crowdURL"));
            currentConfiguration.setCrowdApplicationName(json.getString("crowdApplicationName"));
            currentConfiguration.setCrowdApplicationPassword(Secret.fromString(json.getString("crowdApplicationPassword")));

            LOGGER.log(Level.FINE, "Setting Group Configurations: {0}", json.toString());

            Jenkins.get().save();

        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error while submitting global configurations, error: {0}", e.getMessage());
        }

        FormApply.success("./").generateResponse(request, response, null);
    }



}
