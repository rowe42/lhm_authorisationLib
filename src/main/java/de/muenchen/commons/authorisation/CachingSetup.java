/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.commons.authorisation;

import de.muenchen.commons.authorisation.model.Permissions;
import static java.util.concurrent.TimeUnit.MINUTES;
import javax.cache.CacheManager;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.Duration;
import javax.cache.expiry.TouchedExpiryPolicy;
import org.springframework.boot.autoconfigure.cache.JCacheManagerCustomizer;
import org.springframework.stereotype.Component;

/**
 * Klasse wird benötigt, wenn Cache umgestellt wird bspw. auf EHCache.
 * @author roland
 */
//@Component
public class CachingSetup implements JCacheManagerCustomizer {

    @Override
    public void customize(CacheManager cacheManager) {
        cacheManager.createCache("permissionsCache", new MutableConfiguration<String, Permissions>()
                .setExpiryPolicyFactory(TouchedExpiryPolicy.factoryOf(new Duration(MINUTES, 7)))
//                .setTypes(String.class, Permissions.class)
                .setStoreByValue(false)
                .setStatisticsEnabled(false));

        cacheManager.createCache("KEEPER_CACHE", new MutableConfiguration<String, Permissions>()
                .setExpiryPolicyFactory(TouchedExpiryPolicy.factoryOf(new Duration(MINUTES, 60)))
                .setStoreByValue(false)
                .setStatisticsEnabled(false));

        cacheManager.createCache("ANIMAL_CACHE", new MutableConfiguration<String, Permissions>()
                .setExpiryPolicyFactory(TouchedExpiryPolicy.factoryOf(new Duration(MINUTES, 60)))
                .setStoreByValue(false)
                .setStatisticsEnabled(false));

        cacheManager.createCache("ENCLOSURE_CACHE", new MutableConfiguration<String, Permissions>()
                .setExpiryPolicyFactory(TouchedExpiryPolicy.factoryOf(new Duration(MINUTES, 60)))
                .setStoreByValue(false)
                .setStatisticsEnabled(false));
    }
}
