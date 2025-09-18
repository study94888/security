//package org.javaboy.authserver.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.RequestCache;
//
///**
// * @author shuxian
// * @date 2025-09-18
// * @description
// */
//@Configuration
//public class WebSecurityConfig {
//
//    /**
//     * 显式声明 RequestCache Bean，供 CustomAuthenticationEntryPoint 注入
//     */
//    @Bean
//    public RequestCache requestCache() {
//        return new HttpSessionRequestCache();
//    }
//
//    // 其他安全配置...
//}
