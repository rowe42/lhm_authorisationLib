/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.commons.authorisation;

import de.muenchen.commons.authorisation.model.Permissions;
import static java.util.concurrent.TimeUnit.MINUTES;
import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.Duration;
import javax.cache.expiry.TouchedExpiryPolicy;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Configuration;

/**
 *
 * @author roland
 */
//@Configuration
@EnableCaching
public class PermissionsCache {
    
    private final static String PERMISSIONS_CACHE = "permissionsCache";

//    @Autowired
    private CacheManager cacheManager;

   
    public Cache<String, Permissions> getCache() {
        Cache cache = cacheManager.getCache(PERMISSIONS_CACHE, String.class, Permissions.class);
        if (cache == null) {
            cacheManager.createCache(PERMISSIONS_CACHE, new MutableConfiguration<String, Permissions>()
                    .setExpiryPolicyFactory(TouchedExpiryPolicy.factoryOf(new Duration(MINUTES, 7)))
                    .setTypes(String.class, Permissions.class)
                    .setStoreByValue(false)
                    .setStatisticsEnabled(false));
            cache = cacheManager.getCache(PERMISSIONS_CACHE, String.class, Permissions.class);
        }

        return cache;
    }

}
