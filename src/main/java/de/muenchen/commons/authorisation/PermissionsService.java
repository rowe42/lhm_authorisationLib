/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.commons.authorisation;

import de.muenchen.commons.authorisation.model.Permissions;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Service;

/**
 *
 * @author roland.werner
 */
@Service
public class PermissionsService {

    private static final Logger LOG = Logger.getLogger(PermissionsService.class.getName());

    @Autowired
    private OAuth2RestTemplate oauth2RestTemplate;
    
    @Autowired
    private PermissionsCache permissionsCache;
    
    @Value("${security.oauth2.entitlements.permissionsUri}")
    private String permissionsUrl;

    /**
     * Prüft die permission gegen KeyCloak unter Nutzung des übergebenen Token.
     * Zunächst wird jedoch geprüft, ob der Token noch valide gegenüber der
     * aktuellen Systemzeit ist.
     *
     * @param permission die Permission, die geprüft werden soll
     * @param token der Token, mit dem KeyCloak aufgerufen werden soll
     * @param useCache bei false wird bei jedem Aufruf direkt KeyCloak
     * aufgerufen, bei true wird ein vorgelagerter Cache geprüft
     * @return true wenn zu dem token die permission existiert, false sonst
     */
    public boolean check(String permission, String token, boolean useCache) {
        boolean check = false;

        LOG.fine("Called Entitlements-check with permission " + permission);
        LOG.finer("Token " + token);

        if (isTokenExpired(token)) {
            LOG.warning("Provided token is already expired. Token: " + token);
        } else {
            check = checkPermissionWithEntitlements(permission, token, useCache);
        }

        return check;
    }

    /**
     * Prüft ob der übergebene Token gegenüber der Systemzeit bereits abgelaufen
     * ist.
     *
     * @param token der zu prüfende Token
     * @return true oder false
     */
    private boolean isTokenExpired(String token) {
        boolean expired;
        String claims = retrieveClaimsFromJWT(token);
        LocalDateTime expiredDate = calculateExpirationFromClaims(claims);
        if (expiredDate.isBefore(LocalDateTime.now())) {
            expired = true;
        } else {
            expired = false;
        }
        return expired;
    }

    /**
     * Überprüft die übergebene permission gegen KeyCloak via Entitlements-API.
     *
     * @param permission die zu prüfende Permission
     * @param token der Token, mit dem KeyCloak aufgerufen wird
     * @param useCache falls true, wird zunächst im lokalen Cache nach
     * permissions zu diesem token geschaut
     * @param useKeyCloakApi ob das KeyCloak-JAR genutzt werden soll oder ein
     * direkter REST-Call erfolgen soll
     * @return true wenn zu dem token die permission existiert, false sonst
     */
    private boolean checkPermissionWithEntitlements(String permission, String token, boolean useCache) {
        LOG.fine("Called checkPermissionWithEntitlementsInCache");
        Permissions permissions;

        if (useCache) {
            permissions = fetchPermissionsWithCache(token);
        } else {
            permissions = fetchPermissions(token);
        }

        boolean allowed = permissions.hasPermission(permission);
        LOG.fine("Permission checked, returning: " + allowed);
        return allowed;
    }

    /**
     * Zu dem übergebenen Token werden die zugehörigen Permissions von KeyCloak
     * geholt. Dabei wird zunächst im lokalen Cache geschaut.
     *
     * @param token der Token, mit dem KeyCloak aufgerufen wird
     * @param useKeyCloakApi ob das KeyCloak-JAR genutzt werden soll oder ein
     * direkter REST-Call erfolgen soll
     * @return die Permissions zu diesem Token
     */
    private Permissions fetchPermissionsWithCache(String token) {
        Permissions permissions = retrievePermissionsFromCache(token);

        if (permissions == null || permissions.isEmpty()) {
            //not found in cache 
            LOG.fine("Permissions not found in Cache.");

            permissions = fetchPermissions(token);
        } else {
            LOG.fine("Permissions found in Cache: " + permissions.getPermissions().toString());
        }

        return permissions;
    }

    private Permissions fetchPermissions(String token) {
        String response = oauth2RestTemplate.getForObject(permissionsUrl, String.class);
        JSONObject responseJSON = new JSONObject(response);
        LOG.fine("JSON received from User-Service: " + response);
        Set<String> permissionSet = extractPermissions(responseJSON);
        Permissions permissions = new Permissions();
        permissions.setPermissions(permissionSet);
        addPermissionsToCache(token, permissions);

        LOG.fine("Permissions retrieved from User-Service: " + permissions.getPermissions().toString());

        return permissions;
    }

    /**
     * Holt die Permissions aus dem Cache zu dem übergebenen Key.
     *
     * @param key
     * @return
     */
    private Permissions retrievePermissionsFromCache(String key) {
        Permissions permissions = null;
        Cache.ValueWrapper vw = permissionsCache.getCache().get(key);
        if (vw != null) {
            permissions = (Permissions) vw.get();
        }
        return permissions;
    }

    /**
     * Legt die übergebenen Permissions unter dem übergebenen key im Cache ab.
     *
     * @param key
     * @param permissions
     */
    private void addPermissionsToCache(String key, Permissions permissions) {
        permissionsCache.getCache().put(key, permissions);
    }

    /**
     * Parst die Claims aus dem übergebenen JWT-Token. Das JWT wird dabei
     * zunächst aus dem Base64-Format konvertiert.
     *
     * @param token
     * @return
     */
    private String retrieveClaimsFromJWT(String token) {
        Jwt jwt = JwtHelper.decode(token);
        String claims = jwt.getClaims();
        return claims;
    }

    /**
     * Parst das expirationDate aus den übergebenen Claims.
     *
     * @param claims
     * @return
     */
    private LocalDateTime calculateExpirationFromClaims(String claims) {
        JSONObject responseJSON = new JSONObject(claims);
        long exp = responseJSON.getInt("exp");
        LocalDateTime ldt = LocalDateTime.ofEpochSecond(exp, 0, ZoneOffset.ofHours(2));

        LOG.fine("Calculated ExpirationDate: " + ldt);

        return ldt;
    }

    private Set<String> extractPermissions(JSONObject content) {
        Set<String> resourceSetList = new HashSet<>();
        JSONArray array = content.getJSONArray("permissions");
        if (array != null && array.length() > 0) {
            for (int i = 0; i < array.length(); i++) {
                String resource = (String) array.get(i);
                if (resource != null) {
                    resourceSetList.add(resource);
                } else {
                    throw new RuntimeException("Resource not found");
                }
            }
        }
        return resourceSetList;
    }

}
