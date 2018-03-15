/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.commons.authorisation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import org.springframework.context.annotation.Configuration;

/**
 *
 * @author roland
 */
@Configuration
public class PermissionsCache {
    
    private final static String PERMISSIONS_CACHE = "permissionsCache";

    @Autowired
    private CacheManager cacheManager;
    
    public Cache getCache() {
        return cacheManager.getCache(PERMISSIONS_CACHE);
    }

}
