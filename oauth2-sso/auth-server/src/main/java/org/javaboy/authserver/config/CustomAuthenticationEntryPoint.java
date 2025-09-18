package org.javaboy.authserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author shuxian
 * @date 2025-09-12
 * @description
 */
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {


    private final RequestCache requestCache;

    // 构造函数注入 —— Spring 会从容器找 RequestCache 类型的 Bean
    public CustomAuthenticationEntryPoint(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
    private ObjectMapper mapper = new ObjectMapper();
            public static final String loginUrl  = "https://pre.t.youku.com/yep/page/s_pre/yingyoutest1";
//    public static final String loginUrl = "http://localhost:1201/oauth/login";
    private static final String AUTO_LOGIN_HTML =
            "<!DOCTYPE html><html><head>" +
                    "<meta charset='UTF-8'>" +
                    "<title>登录中...</title>" +
                    "<script type='text/javascript'>" +
                    "    window.onload = function() {" +
                    "        document.forms[0].submit();" +
                    "    }" +
                    "</script>" +
                    "</head><body>" +
                    "<form action='/oauth/login' method='post'>" +
                    "  <input type='hidden' name='username' value='sang' />" +
                    "  <input type='hidden' name='password' value='123' />" +
                    "  <button type='submit'>正在自动登录...</button>" +
                    "</form>" +
                    "</body></html>";
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
        if ("/oauth/authorize".equals(requestUri)) {
//
//            // 保存原始请求，以便登录后跳回
//            new HttpSessionRequestCache().saveRequest(request, response);
//
//            // 返回自动提交的登录表单页面
//            response.setStatus(HttpStatus.OK.value());
//            response.setContentType("text/html;charset=UTF-8");
//            response.getWriter().write(AUTO_LOGIN_HTML);
            // ✅ 使用 Spring Security 的 RequestCache 来保存原始请求

            requestCache.saveRequest(request, response);

            // 🔁 重定向到前端登录页（可以是外部地址）
            String redirectUrl =loginUrl + "?" + request.getQueryString();
//            response.sendRedirect(redirectUrl);
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
//            response.sendRedirect(loginUrl + "?" + request.getQueryString());
        } else {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write(mapper.writeValueAsString(result));
        }

    }
}