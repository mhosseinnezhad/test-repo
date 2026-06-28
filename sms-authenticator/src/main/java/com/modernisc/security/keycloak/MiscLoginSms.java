package com.modernisc.security.keycloak;

import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.HttpClients;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class MiscLoginSms implements SMSService {
    private String endpoint;

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public MiscLoginSms(String endpoint) {
        this.endpoint = endpoint;
    }

    public boolean sendold(String phoneNumber, String message, String login, String pw) {
        System.out.println("message = " + message);
        return true;
    }

    @Override
    public boolean send(String phoneNumber, String message, String clientId, String clientSecret) {

        HttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost(endpoint);
        try (InputStream fileInputStream = this.getClass().getClassLoader().getResourceAsStream("SmsMessageTemplate.txt");
             BufferedReader bis = new BufferedReader(new InputStreamReader(fileInputStream))) {
            StringBuffer sb = new StringBuffer();
            String str;
            while ((str = bis.readLine()) != null)
                sb.append(str);

            String body = sb.toString();
            Map valuesMap = new HashMap();
            valuesMap.put("CLIENT_ID", clientId);
            valuesMap.put("CLIENT_SECRET", clientSecret);
            valuesMap.put("MESSAGE_BODY", message);
            valuesMap.put("PHONE_NUMBER", phoneNumber);
            StrSubstitutor sub = new StrSubstitutor(valuesMap);
            body = sub.replace(body);

            BasicHttpEntity requestEntity = new BasicHttpEntity();
            InputStream is = new ByteArrayInputStream(body.getBytes());
            requestEntity.setContent(is);
            post.setEntity(requestEntity);
            HttpResponse response = client.execute(post);

            HttpEntity entity = response.getEntity();
            if (entity != null) {
                try (InputStream instream = entity.getContent();
                     BufferedReader bis2 = new BufferedReader(new InputStreamReader(instream))) {
                    String line = bis2.readLine();
                    String errorCodeStart = "<errorCode>";
                    if (line.contains(errorCodeStart)) {
                        int closeIndex = line.indexOf(errorCodeStart) + errorCodeStart.length();
                        int openIndex = line.indexOf('<', closeIndex);
                        if (closeIndex > 0 && openIndex > closeIndex) {
                            int errorCode = Integer.parseInt(line.substring(closeIndex, openIndex));
                            return errorCode == 0;
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}