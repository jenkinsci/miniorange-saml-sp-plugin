package org.miniorange.saml;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.logging.Logger;

public class MoSAMLTemplateManager {

    private MoSAMLPluginSettings settings;

    private static final Logger LOGGER = Logger.getLogger(MoSAMLManager.class.getName());

    public MoSAMLTemplateManager(MoSAMLPluginSettings settings) {
        this.settings = settings;
    }

    public void showTestConfigurationResult(MoSAMLResponse samlResponse, HttpServletRequest request,
                                            HttpServletResponse response, MoSAMLException e) throws IOException, MoSAMLException {
        LOGGER.info("Test Configuration called.");
        if (e == null) {
            LOGGER.fine("Test config is being processed");
            String username = "";
            StringBuffer htmlStart = new StringBuffer("<div style=\"font-family:Calibri;padding:0 3%;\">");
            String[] usernameArray = samlResponse.getAttributes().get(settings.getUsernameAttribute());
            if (usernameArray != null && usernameArray.length == 1) {
                username = usernameArray[0];
            }
            if (StringUtils.isBlank(username)) {
                LOGGER.fine("username is blank");
                htmlStart = htmlStart.append("<div style=\"color: #a94442;background-color: #f2dede;padding: 15px;"
                        + "margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;\">TEST "
                        + "FAILED</div><div style=\"color: #a94442;font-size:14pt; margin-bottom:20px;\">WARNING: Username "
                        + "attribute not found in the response. Users will not be able to login. [Please check Username attribute in User profile tab it should be similar to attribute value in IDP.]</div>");
            } else {
                LOGGER.fine("username is not blank " + username);
                htmlStart = htmlStart.append("<div style=\"color: #3c763d;background-color: #dff0d8; padding:2%;"
                        + "margin-bottom:20px;text-align:center; border:1px solid #AEDB9A; font-size:18pt;\">TEST "
                        + "SUCCESSFUL</div>");
            }
            htmlStart = htmlStart.append("<span style=\"font-size:14pt;\"><b>Hello</b>, " + username + "</span><br/>"
                    + "<p style=\"font-weight:bold;font-size:14pt;margin-left:1%;\">ATTRIBUTES RECEIVED:</p>"
                    + "<table style=\"border-collapse:collapse;border-spacing:0; display:table;width:100%; "
                    + "font-size:14pt;background-color:#EDEDED;\"><tr style=\"text-align:center;\">"
                    + "<td style=\"font-weight:bold;border:2px solid #949090;padding:2%;\">ATTRIBUTE NAME</td>"
                    + "<td style=\"font-weight:bold;padding:2%;border:2px solid #949090; word-wrap:break-word;\">"
                    + "ATTRIBUTE VALUE</td></tr>");
            Iterator<String> it = samlResponse.getAttributes().keySet().iterator();
            while (it.hasNext()) {
                String key = it.next();
                htmlStart = htmlStart.append("<tr><td style=\"font-weight:bold;border:2px solid #949090;padding:2%;\">"
                        + key + "</td><td style=\"padding:2%;border:2px solid #949090;word-wrap:break-word;\">");

                String[] values = samlResponse.getAttributes().get(key);
                htmlStart = htmlStart.append(StringUtils.join(values, "<hr/>"));
                htmlStart = htmlStart.append("</td></tr>");
            }
            htmlStart = htmlStart.append("</table></div>");
            htmlStart = htmlStart
                    .append("<div style=\"margin:3%;display:block;text-align:center;\"><input style=\"padding:1%;"
                            + "width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;"
                            + "border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;"
                            + "box-sizing:border-box;border-color: #0073AA;box-shadow:0px 1px 0px rgba(120,200,230,0.6) inset;"
                            + "color: #FFF;\" type=\"button\" value=\"Done\" onClick=\"self.close();\"></div>");
            response.setCharacterEncoding("iso-8859-1");
            response.setContentType("text/html");
            response.getOutputStream().write(htmlStart.toString().getBytes(StandardCharsets.UTF_8));
        } else {
            LOGGER.fine("Test config is failed ");
            StringBuffer htmlStart = new StringBuffer("<div style=\"font-family:Calibri;padding:0 3%;\">");
            htmlStart = htmlStart
                    .append("<div style=\"color:#a94442;background-color:#f2dede;padding:15px;margin-bottom:20px;"
                            + "text-align:center;border:1px solid #E6B3B2;font-size:18pt;\">TEST FAILED</div>");
            htmlStart = htmlStart
                    .append("<table style=\"border-collapse:collapse;border-spacing:0; display:table;width:100%;"
                            + "font-size:14pt;\"><tr style=\"padding-top:10px;padding-bottom:10px;\"><td style=\"font-weight:bold;"
                            + "padding:10px 5px 10px 5px;\">Error Code</td><td style=\"word-wrap:break-word;\">"
                            + e.getErrorCode()
                            + "</td></tr><tr><td style=\"font-weight:bold;padding:10px 5px 10px 5px;\">"
                            + "Error Message</td><td style=\"word-wrap:break-word;\">" + e.getMessage()
                            + "</td></tr><tr>"
                            + "<td style=\"font-weight:bold;padding:10px 5px 10px 5px;\">Resolution</td>"
                            + "<td style=\"word-wrap:break-word;\">" + e.getResolution() + "</tr></table></div>");
            response.setContentType("text/html");
            response.setCharacterEncoding("iso-8859-1");
            response.getOutputStream().write(htmlStart.toString().getBytes(StandardCharsets.UTF_8));
        }
    }
}
