//package org.javaboy.authserver.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
//import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
//import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
//import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
//
///**
// * @author shuxian
// * @date 2025-09-13
// * @description
// */
//@Configuration
//@EnableResourceServer  // 启用资源服务器
//public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
//
//    @Autowired
//    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
//    @Autowired
//    private CookieTokenFilter cookieTokenFilter; // 注入你的 filter
//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
//        resources.resourceId("res1") // 必须和 client 配置中的 resourceId 一致
//                .authenticationEntryPoint(customAuthenticationEntryPoint); // 自定义未登录响应
//    }
//
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/hello").authenticated() // 需要 token 才能访问
//                .anyRequest().permitAll()
//                .and()
//                .exceptionHandling()
//                .and()
//                .csrf().disable()
//                // ✅ 在资源服务器的 FilterChain 中显式添加你的过滤器
//                .addFilterBefore(cookieTokenFilter, OAuth2AuthenticationProcessingFilter.class)
//        ;
//    }
//}
