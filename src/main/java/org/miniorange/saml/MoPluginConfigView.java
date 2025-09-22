package org.miniorange.saml;


import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.SecurityRealm;
import hudson.util.FormApply;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.io.IOUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.kohsuke.stapler.verb.POST;

import javax.servlet.ServletException;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static jenkins.model.Jenkins.get;

@Extension
public class MoPluginConfigView extends ManagementLink {
    private static final Logger LOGGER = Logger.getLogger(MoPluginConfigView.class.getName());

    final String PREMIUM_PLUGIN_URL = "https://miniorange.s3.amazonaws.com/public/plugins/Jenkins/jenkins-saml-sso-premium-3.5.0.hpi";
    final String GOOGLE_SHEET_SCRIPT = "https://script.google.com/macros/s/AKfycbyn-Pko2kV_XHTHdSnlhwZMYSMN3pOagmqgCfMnAb5tTrWeA47vOj1NolZSgikChRdW/exec";

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

    public MoGroupConfiguration getGroupsConfiguration(){
        return new MoGroupConfiguration();
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
    @Restricted(NoExternalUse.class)
    public void doConfirmationFormSubmit(StaplerRequest request, StaplerResponse response) throws IOException {

        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String orgName = request.getParameter("orgName");

        if(name.length()>50){
            LOGGER.fine("Invalid name.");
            response.getWriter().write("Not a valid Name.");
            return;
        }

        if(orgName.length()>100){
            LOGGER.fine("Invalid Organization name.");
            response.getWriter().write("Not a valid organization name.");
            return;
        }

        //Email validation
        String regex = "^(.+)@(.+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        if (!matcher.matches()) {
            LOGGER.fine("Invalid email address: " + email);
            response.getWriter().write("Not a valid email address.");
            return;
        }


        String url = GOOGLE_SHEET_SCRIPT
                    + "?name=" + URLEncoder.encode(name, "UTF-8")
                    + "&email=" + URLEncoder.encode(email, "UTF-8")
                    + "&query=" + URLEncoder.encode(orgName, "UTF-8");

        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "*/*");
            connection.setDoOutput(true);

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                LOGGER.fine("Form submitted successfully!");
                response.getWriter().write("Form submitted successfully!");
            } else {
                LOGGER.fine("Error submitting form. Response Code: " + responseCode);
                response.getWriter().write("Error submitting form. Response Code: " + responseCode);
            }
        } catch (Exception e) {
            LOGGER.fine("Error submitting form. Response Code: " + e.getMessage());
            response.getWriter().write("Error: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public void doInstallPlugin(StaplerRequest req, StaplerResponse rsp) throws IOException {
        LOGGER.fine("Starting plugin installation...");

        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) throw new IllegalStateException("Jenkins instance is not available.");

        String pluginName = "miniorange-saml-sp";

        File pluginsDir = new File(jenkins.getRootDir(), "plugins");
        pluginsDir.mkdirs();

        File pluginFile = new File(pluginsDir, pluginName + ".jpi");

        try (InputStream in = new URL(PREMIUM_PLUGIN_URL).openStream()) {
            Files.copy(in, pluginFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            LOGGER.fine("Plugin downloaded and installed at: " + pluginFile.getAbsolutePath());

        } catch (IOException e) {
            LOGGER.fine("Error downloading the plugin: " + e.getMessage());
            throw e;
        }

        // Ensure Jenkins picks up the new plugin
        pluginFile.setLastModified(System.currentTimeMillis());

        LOGGER.fine("Plugin installed successfully. Restart Jenkins for changes to take effect.");
        rsp.sendRedirect(req.getContextPath() + "/manage/RestartPlugin");
        // Trigger a safe restart to apply the changes
        try {
            jenkins.safeRestart();
            LOGGER.fine("Jenkins safe restart triggered successfully.");
        } catch (Exception e) {
            LOGGER.fine("Failed to restart Jenkins: " + e.getMessage());
            throw new IOException("Error triggering Jenkins restart.", e);
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



