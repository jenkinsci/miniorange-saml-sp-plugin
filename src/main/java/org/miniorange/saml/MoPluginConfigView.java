package org.miniorange.saml;


import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.SecurityRealm;
import hudson.util.FormApply;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.io.IOUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.servlet.ServletException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.logging.Logger;

import static jenkins.model.Jenkins.get;

@Extension
public class MoPluginConfigView extends ManagementLink {
    private static final Logger LOGGER = Logger.getLogger(MoPluginConfigView.class.getName());

    @RequirePOST
    @Restricted(NoExternalUse.class)
    @SuppressWarnings("unused")
    public void doSaveConfiguration(StaplerRequest request, StaplerResponse response) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        request.setCharacterEncoding("UTF-8");
        net.sf.json.JSONObject json = request.getSubmittedForm();
        MoSAMLAddIdp.DESCRIPTOR.doRealmSubmit(request, response, json);
        FormApply.success(request.getContextPath() + "/").generateResponse(request, response, null);
    }

    @NonNull
    public String getCategoryName() {
        return "SECURITY";
    }


    @CheckForNull
    @SuppressWarnings("unused")
    public SecurityRealm getRealm() {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        if (realm instanceof MoSAMLAddIdp) {
            return realm;
        } else {
            return null;
        }
    }


    @NonNull
    @Override
    public String getIconFileName() {
        String icon = null;
        if (Jenkins.get().getSecurityRealm() instanceof MoSAMLAddIdp) {
            icon = "symbol-id-card";
        }
        return icon;
    }

    @NonNull
    @Override
    public String getDisplayName() {
        return "miniOrange SAML SSO";
    }


    @NonNull
    @Override
    public String getUrlName() {
        return "MoPluginConfigView";
    }

    @Override
    public String getDescription() {
        return "Secure Single Sign-On (SSO) solution that allows user to login to their apps using   IDP credentials by SAML Authentication.";
    }

    @SuppressWarnings("unused")
    public void doDownload(StaplerRequest req, StaplerResponse rsp) throws IOException {

        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/octet-stream");
        rsp.setHeader("Content-Disposition", "attachment; filename=MoSamlConfiguration.json");

        SecurityRealm realm = get().getSecurityRealm();
        if( realm instanceof MoSAMLAddIdp){

            String content = realm.toString();
            File MoSamlConfiguration = new File("MoSamlConfiguration.json");

            try (OutputStreamWriter writer = new OutputStreamWriter(Files.newOutputStream(MoSamlConfiguration.toPath()), StandardCharsets.UTF_8)) {
                try (PrintWriter printWriter = new PrintWriter(writer)) {
                    printWriter.println(content);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            try (FileInputStream in = new FileInputStream(MoSamlConfiguration)) {
                IOUtils.copy(in, rsp.getOutputStream());
            } finally {
                if (MoSamlConfiguration.exists()) {
                    MoSamlConfiguration.delete();
                }
            }
        }
    }

    @RequirePOST
    @SuppressWarnings("unused")
    public void doUploadSamlConfigJson(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        try {
            FileItem fileItem = req.getFileItem("moSamlJsonConfiguration");
            String fileContent = fileItem.getString();
            JSONObject json = JSONObject.fromObject(fileContent);
            MoSAMLAddIdp.DESCRIPTOR.doRealmSubmit(req, rsp, json);
        } catch(Exception e) {
            LOGGER.fine("Error occur while uploading Saml config file: " + e.getMessage());
        }
        FormApply.success("./").generateResponse(req, rsp, null);
    }

}



