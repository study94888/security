package org.javaboy.authserver.config;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author shuxian
 * @date 2025-09-18
 * @description
 */
@Service
public class OAuthRequestStore {
    private final Map<String, String> pending = new ConcurrentHashMap<>();

    public String save(String originalUrl) {
        String state = UUID.randomUUID().toString();
        pending.put(state, originalUrl);
        return state;
    }

    public String remove(String state) {
        return pending.remove(state);
    }
}
