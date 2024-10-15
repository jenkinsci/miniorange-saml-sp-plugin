package org.miniorange.saml.crowdIntegration;

import hudson.model.User;
import hudson.util.Secret;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.miniorange.saml.MoSAMLPluginSettings;
import org.miniorange.saml.MoHttpUtils;

import javax.imageio.IIOException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Logger;

public class MoSAMLCrowdGroupManagement {
    private static final Logger LOGGER = Logger.getLogger(MoSAMLCrowdGroupManagement.class.getName());

    String CROWD_USER_GROUP_FETCH_URL = "/rest/usermanagement/1/user/group/direct?username=";

    private String fetchGroupDataFromCrowd(String username, MoSAMLPluginSettings settings)
    {
        try {
            String applicationName = settings.getCrowdApplicationName();
            Secret password = settings.getCrowdApplicationPassword();

//         String url=http://localhost:8095/crowd/rest/usermanagement/1/user/group/nested?username=test
            String url = settings.getCrowdURL() + CROWD_USER_GROUP_FETCH_URL + username;
            LOGGER.info("Get request to fetch groups from crowd " + url);

            String response = MoHttpUtils.sendGetRequest(url, getAuthorizationHeaders(
                    applicationName,password.getPlainText()));
            return response;

        }catch (IOException e) {
            LOGGER.fine("An exception occurred while sending get request: " + e.getMessage());
            throw new RuntimeException(e);
        }

    }

    public ArrayList<String> directGroupsFromCrowd(MoSAMLPluginSettings settings, User user){
        String username=user.getId();
        LOGGER.info("username is : "+username);
        String recievedResponse= fetchGroupDataFromCrowd(username,settings);
        LOGGER.fine("recievedResponse from fetchGroupDataFromCrowd : "+recievedResponse);
        return parseResponseAndGetAttribute(recievedResponse);
    }

    private ArrayList<String> parseResponseAndGetAttribute(String recievedResponse) {
        int i=0;
        ArrayList<String> groupListFromCrowd = new ArrayList<>();
        if (!StringUtils.isBlank(recievedResponse) && !recievedResponse.equals("Empty"))
        {
            JSONObject userInfo= new JSONObject(recievedResponse);
            JSONArray groupArray= userInfo.optJSONArray("groups");
            while (i < groupArray.length())
            {
                JSONObject subgroupJSONObject= groupArray.optJSONObject(i);
                String groupName= subgroupJSONObject.optString("name");
                groupListFromCrowd.add(groupName);
                i++;
            }
        }
        else if(recievedResponse.equals("Empty"))groupListFromCrowd.add("Empty");
        return groupListFromCrowd;
    }

    private static HashMap<String, String> getAuthorizationHeaders(String applicationName, String password) {
        LOGGER.fine("in getAuthorizationHeaders ");
        HashMap<String, String> headers = new HashMap<String, String>();
        String auth = applicationName + ":" + password;
        byte[] encodedAuth = Base64.encodeBase64(
                auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + new String(encodedAuth,StandardCharsets.UTF_8);
        headers.put("Authorization",authHeader);
        headers.put("Accept","application/json");
        LOGGER.fine("Headers"+headers);
        return headers;
    }



}
