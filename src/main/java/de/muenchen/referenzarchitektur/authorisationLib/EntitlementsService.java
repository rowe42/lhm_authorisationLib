/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.referenzarchitektur.authorisationLib;

import de.muenchen.referenzarchitektur.authorisationLib.model.Permissions;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.representation.EntitlementResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author roland.werner
 */
@Service
public class EntitlementsService {

    private static final Logger LOG = Logger.getLogger(EntitlementsService.class.getName());

//    protected OAuth2RestTemplate oauth2Template;
    @Value("${security.oauth2.entitlements.entitlementsUri}")
    private String authUrl;

    //hack: Entitlements "Cache": token --> permissions
    //TODO muss durch einen richtigen Cache ersetzt werden, der nicht vollläuft!!!
    private Map<String, Permissions> permissionsCache = new HashMap<>();

    /**Prüft die permission gegen KeyCloak unter Nutzung des übergebenen Token.
     * Zunächst wird jedoch geprüft, ob der Token noch valide gegenüber der aktuellen
     * Systemzeit ist.
     *
     * @param permission die Permission, die geprüft werden soll
     * @param token der Token, mit dem KeyCloak aufgerufen werden soll
     * @param useKeyCloakApi ob das KeyCloak-JAR genutzt werden soll oder ein direkter REST-Call erfolgen soll
     * @param useCache bei false wird bei jedem Aufruf direkt KeyCloak aufgerufen, bei true wird ein vorgelagerter Cache geprüft 
     * @return true wenn zu dem token die permission existiert, false sonst
     */
    public boolean check(String permission, String token, boolean useKeyCloakApi, boolean useCache) {
        boolean check;

        LOG.fine("Called Entitlements-check with permission " + permission);
        LOG.finer("Token " + token);

        if (isTokenExpired(token)) {
            LOG.warning("Provided token is already expired. Token: " + token);
            check = false;
        }

        check = checkPermissionWithEntitlements(permission, token, useCache, useKeyCloakApi);
        return check;
    }

    /**
     * Prüft ob der übergebene Token gegenüber der Systemzeit bereits abgelaufen ist.
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
     * @param useCache falls true, wird zunächst im lokalen Cache nach permissions zu diesem token geschaut
     * @param useKeyCloakApi ob das KeyCloak-JAR genutzt werden soll oder ein direkter REST-Call erfolgen soll
     * @return true wenn zu dem token die permission existiert, false sonst
     */
    private boolean checkPermissionWithEntitlements(String permission, String token, boolean useCache, boolean useKeyCloakApi) {
        LOG.fine("Called checkPermissionWithEntitlementsInCache");
        Permissions permissions;
        
        if (useCache) {
            permissions = fetchPermissionsWithCache(token, useKeyCloakApi);
        } else {
            permissions = fetchPermissions(token, useKeyCloakApi);
        }
        
        boolean allowed = permissions.hasPermission(permission);
        LOG.fine("Permission checked, returning: " + allowed);
        return allowed;
    }


    /**
     * Zu dem übergebenen Token werden die zugehörigen Permissions von KeyCloak geholt.
     * Dabei wird zunächst im lokalen Cache geschaut.
     * 
     * @param token der Token, mit dem KeyCloak aufgerufen wird
     * @param useKeyCloakApi  ob das KeyCloak-JAR genutzt werden soll oder ein direkter REST-Call erfolgen soll
     * @return die Permissions zu diesem Token
     */
    private Permissions fetchPermissionsWithCache(String token, boolean useKeyCloakApi) {
        Permissions permissions = retrievePermissionsFromCache(token);

        if (permissions == null || permissions.isEmpty()) {
            //not found in cache 
            LOG.fine("Permissions not found in Cache.");

            permissions = fetchPermissions(token, useKeyCloakApi);
        } else {
            LOG.fine("Permissions found in Cache: " + permissions.getPermissions().toString());
        }

        return permissions;
    }

    /**
     * Zu dem übergebenen Token werden die zugehörigen Permissions von KeyCloak geholt.
     * @param token der Token, mit dem KeyCloak aufgerufen wird
     * @param useKeyCloakApi ob das KeyCloak-JAR genutzt werden soll oder ein direkter REST-Call erfolgen soll
     * @return die Permissions zu diesem Token
     */
    private Permissions fetchPermissions(String token, boolean useKeyCloakApi) {
        Permissions permissions = new Permissions();

        String rpt;
        if (useKeyCloakApi) {
            rpt = retrieveRPTviaEntitlementsWithKeyCloakAPI(token);
        } else {
            rpt = retrieveRPTviaEntitlements(token);
        }

        Set<String> permissionsSet = extractPermissionsFromRPT(rpt);
        permissions.setPermissions(permissionsSet);
        addPermissionsToCache(token, permissions);

        LOG.fine("Permissions retrieved from KeyCloak: " + permissions.getPermissions().toString());

        return permissions;
    }

    /**
     * Holt die Permissions aus dem Cache zu dem übergebenen Key.
     * @param key 
     * @return 
     */
    private Permissions retrievePermissionsFromCache(String key) {
        return permissionsCache.get(key);
    }

    /**
     * Legt die übergebenen Permissions unter dem übergebenen key im Cache ab.
     * @param key
     * @param permissions 
     */
    private void addPermissionsToCache(String key, Permissions permissions) {
        permissionsCache.put(key, permissions);
    }

    /**
     * Parst die Claims aus dem übergebenen JWT-Token. Das JWT wird dabei zunächst aus dem Base64-Format konvertiert.
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

    /**
     * Ruft die Entitlements-API direkt über RestTemplate auf und holt das RPT-Token.
     *
     * @param token das Token, das an KeyCloak gesendet wird
     * @return das RPT-Token
     */
    private String retrieveRPTviaEntitlements(String token) {
        LOG.fine("Called retrieveRPTviaEntitlements");

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);

        HttpEntity entity = new HttpEntity(headers);

        ResponseEntity<String> responseEntity = restTemplate.exchange(
                authUrl, HttpMethod.GET, entity, String.class);

//        String response = this.oauth2Template.getForObject(authUrl, String.class);
        String response = responseEntity.getBody();

        JSONObject responseJSON = new JSONObject(response);
        
        String rpt = responseJSON.getString("rpt");
        LOG.fine("Got this RPT: " + rpt);
        return rpt;
    }

    /**
     * Ruft die Entitlements-API über das KeyCloak-JAR auf und holt das RPT-Token.
     *
     * @param token das Token, das an KeyCloak gesendet wird
     * @return das RPT-Token
     */
    private String retrieveRPTviaEntitlementsWithKeyCloakAPI(String token) {
        LOG.fine("Called retrieveRPTviaEntitlementsWithKeyCloakAPI");
        
        AuthzClient authzClient = AuthzClient.create();

        EntitlementResponse response = authzClient.entitlement(token)
                .getAll("openIdDemo");
        String rpt = response.getRpt();
        LOG.fine("Got this RPT: " + rpt);
        return rpt;
    }

    /**
     * Parst die Permissions aus dem übergebenen RPT-Token. Das RPT-Token wird dabei zunächst aus dem Base64-Format konvertiert.
     * @param rpt
     * @return
     */
    public Set<String> extractPermissionsFromRPT(String rpt) {
        Set<String> resourceSetList = new HashSet<>();
        Jwt jwt = JwtHelper.decode(rpt);
        if (jwt != null) {
            String claims = jwt.getClaims();
            if (claims != null) {
                JSONObject json = new JSONObject(claims);
                if (json != null) {
                    JSONObject authorization = json.getJSONObject("authorization");
                    if (authorization != null) {
                        JSONArray array = authorization.getJSONArray("permissions");
                        if (array != null && array.length() > 0) {
                            for (int i = 0; i < array.length(); i++) {
                                JSONObject resource = (JSONObject) array.get(i);
                                if (resource != null && resource.get("resource_set_name") != null) {
                                    String resourceSetName = resource.get("resource_set_name").toString();
                                    resourceSetList.add(resourceSetName);
                                } else {
                                    throw new RuntimeException("Resource not found");
                                }
                            }
                        } else {
                            throw new RuntimeException("permissions not filled");
                        }
                    } else {
                        throw new RuntimeException("Array not filled");
                    }
                } else {
                    throw new RuntimeException("authorization not filled");
                }
            } else {
                throw new RuntimeException("claims not filled");
            }
        } else {
            throw new RuntimeException("no claims");
        }
        return resourceSetList;
    }

}
