package org.javaboy.authserver.config;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * @author shuxian
 * @date 2025-09-18
 * @description
 */


@Component
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        if ("sang".equals(username) || "admin".equals(username) ) {
            // 构造一个用户，密码设为 null 或占位符
            return User.builder()
                    .username(username)
                    .password("1") // 占位
                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .disabled(false)
                    .build();
//        }
//        throw new UsernameNotFoundException("User not found: " + username);
    }
}
