/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.referenzarchitektur.authorisationLib;

import java.io.Serializable;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Service;

/**
 *
 * @author Roland.Werner
 */
@Service
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private static final Logger LOG = Logger.getLogger(CustomPermissionEvaluator.class.getName());
    
    @Autowired    
    private PermissionsService entitlementsService;
    
    @Override
    public boolean hasPermission(Authentication a, Object o, Object o1) {
        return hasPermission(a, 1, (String) o, o1);
    }

    /**
     * Prüft die übergebene Permission gegen KeyCloak. Holt sich dafür den Token des aktuellen Users.
     * @param a
     * @param srlzbl
     * @param permission die zu überprüfende Permission
     * @param methodObject welche Methode anzuwenden ist: a) Entitlements, b) EntitlementsKeyCloakAPI, c) EntitlementsNoCache
     * @return 
     */
    @Override
    public boolean hasPermission(Authentication a, Serializable srlzbl, String permission, Object methodObject) {
        LOG.fine("-----------------------------------------");
        LOG.fine("--------- hasPermission called. ---------");
        LOG.fine("-----------------------------------------");
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) a.getDetails();
        String tokenValue = details.getTokenValue();          
        
        String method = (String) methodObject;
        
        boolean allowed = false;
        if (method.equals("Entitlements")) {
            allowed = this.entitlementsService.check(permission, tokenValue, true);
        } else if (method.equals("EntitlementsNoCache")) {
            allowed = this.entitlementsService.check(permission, tokenValue, false);
        }  
        else {
            LOG.severe("Supplied method " + method + " not supported!");
        }
        return allowed;
    }
    
}
