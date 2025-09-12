package org.javaboy.client2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import java.util.Map;


/**
 * @author shuxian
 * @date 2025-09-12
 * @description
 */
@RestController
public class TokenExchangeController {

    private final View error;
    @Value("${security.oauth2.client.access-token-uri}")
    private String tokenUri;

    public TokenExchangeController(View error) {
        this.error = error;
    }

    @GetMapping("/oauth2/callback")
    public ResponseEntity<?> exchangeCode(CodeRequest request) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", request.getCode());
        params.add("redirect_uri", "http://localhost:1204/oauth2/callback");
        if (request.getCodeVerifier() != null) {
            params.add("code_verifier", request.getCodeVerifier()); // PKCE
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth("javaboy", "123");

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);
        System.out.println("URL: " + tokenUri);
        System.out.println("Headers: " + headers);
        System.out.println("Body: " + params);
        try {
            ResponseEntity<Map> response = new RestTemplate()
                    .postForEntity(tokenUri, entity, Map.class);
            return ResponseEntity.ok(response.getBody()); // ✅ 把 JWT 返回前端
        } catch (HttpClientErrorException e) {
            // ✅ 打印详细错误
            System.err.println("Token request failed: " + e.getStatusCode());
            System.err.println("Response: " + e.getResponseBodyAsString());
            return null;
        }
    }


    static class CodeRequest {
        private String code;
        private String redirectUri;
        private String codeVerifier;

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public void setCodeVerifier(String codeVerifier) {
            this.codeVerifier = codeVerifier;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }
// getter/setter
    }
}
