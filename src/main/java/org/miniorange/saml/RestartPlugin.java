package org.miniorange.saml;

import hudson.Extension;
import hudson.model.ManagementLink;

@Extension
public class RestartPlugin extends ManagementLink {

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getDescription() {
        return "Restart Jenkins after plugin installation.";
    }

    @Override
    public String getUrlName() {
        return "RestartPlugin";
    }
}
