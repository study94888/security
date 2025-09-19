package org.javaboy.client2.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author shuxian
 * @date 2025-09-12
 * @description
 */
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private ObjectMapper mapper = new ObjectMapper();

    @Value("${security.oauth2.client.user-authorization-uri}")
    private String authServerUri;
    @Value("${security.oauth2.client_server.url}")
    private String CLIENT_SERVER;
    @Value("${security.oauth2.client.client-id}")
    private String CLIENT_ID;
//    public static final String callbackUrl = "https://www.baidu.com";
    public static final String callbackUrl = "https://ax2.youku.com:1204"+"/oauth/callback";
//    public static final String callbackUrl = "https://ax2.youku.com:1201/hello";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws ServletException, IOException {
//            Map<String, Object> map = new HashMap<String, Object>();
//            Throwable cause = authException.getCause();
//            if(cause instanceof InvalidTokenException) {
//                map.put("code", 401);//401
//                map.put("msg", "无效的token");
//            }else{
//                map.put("code", "UNAUTHORIZED");//401
//                map.put("msg", "访问此资源需要完全的身份验证");
//            }
        // 如果是 /oauth/authorize 请求，且用户未登录
        String requestUri = request.getRequestURI();
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        result.put("code", 1001);
        result.put("msg", "用户未登录，请前往登录");

//
//        if ("/oauth/authorize".equals(requestUri)) {
//            // 保存原始请求参数，以便登录后重试
//            String query = request.getQueryString() != null ? "?" + request.getQueryString() : "";
//            String fullUri = requestUri + query;
//
//            // 存入 session，登录成功后跳转回来
//            request.getSession().setAttribute("saved_request_uri", fullUri);
//
//            // 返回 JSON 提示，前端可据此跳转登录页
//            response.setStatus(HttpStatus.UNAUTHORIZED.value());
//            response.setContentType("application/json;charset=UTF-8");
//            result.put("data", null);
//            result.put("redirect", "/oauth/login"); // 前端可跳转到这里
//            ObjectMapper mapper = new ObjectMapper();
//            response.getWriter().write(mapper.writeValueAsString(result));
//
//
//        } else {
//            response.setContentType("application/json;charset=UTF-8");
//            response.setStatus(HttpStatus.UNAUTHORIZED.value());
//            response.getWriter().write(mapper.writeValueAsString(result));
//        }
        String redirectUri = authServerUri +"?"+"client_id="+CLIENT_ID+"&redirect_uri="+callbackUrl+"&response_type=code&username=sang&password=123";
        response.sendRedirect(redirectUri);

    }
}