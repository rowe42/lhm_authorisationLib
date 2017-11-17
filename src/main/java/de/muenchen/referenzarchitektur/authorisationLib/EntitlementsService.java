/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.referenzarchitektur.authorisationLib;

import de.muenchen.referenzarchitektur.authorisationLib.model.TimedPermissions;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
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

    //hack: Entitlements "Cache": user --> permissions
    private Map<String, TimedPermissions> permissions = new HashMap<>();

//    public EntitlementsService(OAuth2RestTemplate oauth2Template) {
//        this.oauth2Template = oauth2Template;
//    }

    /**
     * check (Entitlements)
     *
     * @param permission
     * @param token
     * @return
     */
    public boolean check(String permission, String token, boolean useKeyCloakApi) {
        LOG.info("Called method2 (Entitlements) with permission " + permission);
        LOG.info("Token " + token);
        String claims = retrieveClaimsFromJWT(token);
        LocalDateTime refreshDate = calculateExpirationFromJWT(claims);
        String user = retrieveUsernameFromToken(claims);
        LOG.info("Retrieved from token: username " + user + " refreshDate " + refreshDate);
        return checkPermissionWithEntitlementsInCache(user, refreshDate, permission, token, useKeyCloakApi);
    }

    public Set<String> getPermissions(boolean useKeyCloakApi) {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) a.getDetails();
        String tokenValue = details.getTokenValue();
        String claims = retrieveClaimsFromJWT(tokenValue);

        //String userName = ((java.util.LinkedHashMap) a.getUserAuthentication().getDetails()).get("preferred_username");
        String userName = retrieveUsernameFromToken(claims);
        LOG.info("User: " + userName);
        
        LocalDateTime refreshDate = calculateExpirationFromJWT(claims);
        TimedPermissions timedPermissions = fetchPermissions(userName, refreshDate, tokenValue, useKeyCloakApi);
        Set<String> permissionSet = timedPermissions.getPermissions();
        if (permissionSet != null) {
            LOG.info("Permissions " + permissionSet.toString());
        }
        return permissionSet;
    }
    
    
    private TimedPermissions fetchPermissions(String user, LocalDateTime expiration, String token, boolean useKeyCloakApi) {
        TimedPermissions timedPermissions = retrievePermissionsFromCache(user);
        LocalDateTime refreshDate = null;
        if (timedPermissions != null) {
            LOG.info("Found Permissions in cache: " + timedPermissions.getPermissions().toString());
            refreshDate = timedPermissions.getRefreshDate();
        } else {
            LOG.info("No Permissions in cache");
            timedPermissions = new TimedPermissions();
        }

        if (refreshDate == null || refreshDate.isBefore(LocalDateTime.now())) {
            //not found in cache or no longer valid --> fetch new
            LOG.info("Permissions no longer valid. RefreshDate: " + refreshDate + ", Now is " + LocalDateTime.now());

            String rpt;
            if (useKeyCloakApi) {
                rpt = retrieveRPTviaEntitlementsWithKeyCloakAPI(token);
            } else {
                rpt = retrieveRPTviaEntitlements(token);
            }

            Set<String> permissionsSet = extractPermissionsFromRPT(rpt);
            timedPermissions.setPermissions(permissionsSet);
            timedPermissions.setRefreshDate(expiration);
            addPermissionsToCache(user, timedPermissions);

            LOG.info("Permissions of user: " + timedPermissions.getPermissions().toString());
        }
        return timedPermissions;
    }

    /**
     * Check Permission with Entitlements. Check Cache first.
     *
     * @param user
     * @param expiration
     * @param permission
     * @return
     */
    private boolean checkPermissionWithEntitlementsInCache(String user, LocalDateTime expiration, String permission, String token, boolean useKeyCloakApi) {
        LOG.info("Called checkPermissionWithEntitlementsInCache");
        TimedPermissions timedPermissions = fetchPermissions(user, expiration, token, useKeyCloakApi);
        boolean allowed = timedPermissions.hasPermission(permission);
        LOG.info("Permission checked, returning: " + allowed);
        return allowed;
    }

    private TimedPermissions retrievePermissionsFromCache(String user) {
        return permissions.get(user);
    }

    private void addPermissionsToCache(String user, TimedPermissions timedPermissions) {
        permissions.put(user, timedPermissions);
    }

    private String retrieveClaimsFromJWT(String base64Token) {
        Jwt jwt = JwtHelper.decode(base64Token);
        String claims = jwt.getClaims();
        return claims;
    }

    private LocalDateTime calculateExpirationFromJWT(String base64Token) {
        JSONObject responseJSON = new JSONObject(base64Token);
        long exp = responseJSON.getInt("exp");
        LocalDateTime ldt = LocalDateTime.ofEpochSecond(exp, 0, ZoneOffset.ofHours(2));

        //long iat = responseJSON.getInt("iat");
        //LocalDateTime ldt = LocalDateTime.now().plusSeconds(exp - iat);
        LOG.info("Calculated RefreshDate: " + ldt);

        return ldt;
    }

    /**
     * Calls Entitlements-API directly without KeyCloak-specific Code.
     *
     * @return The retrieved RPT
     */
    private String retrieveRPTviaEntitlements(String token) {
        LOG.info("Called retrieveEntitlements");

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);

        HttpEntity entity = new HttpEntity(headers);

        ResponseEntity<String> responseEntity = restTemplate.exchange(
                authUrl, HttpMethod.GET, entity, String.class);

//        String response = this.oauth2Template.getForObject(authUrl, String.class);
        String response = responseEntity.getBody();
        LOG.info("Body " + response);

        JSONObject responseJSON = new JSONObject(response);

        LOG.info("entitlements retrieved");
        return responseJSON.getString("rpt");
    }

    /**
     * Calls Entitlements-API with the help of keycloak specific classes.
     *
     * @param token The User Access Token
     * @return The retrieved RPT
     */
    private String retrieveRPTviaEntitlementsWithKeyCloakAPI(String token) {
        AuthzClient authzClient = AuthzClient.create();

        EntitlementResponse response = authzClient.entitlement(token)
                .getAll("openIdDemo");
        String rpt = response.getRpt();
        LOG.info("Got this RPT: " + rpt);
        return rpt;
    }

    public String retrieveUsernameFromToken(String token) {
        JSONObject responseJSON = new JSONObject(token);
        String username = responseJSON.getString("preferred_username");
        return username;
    }

    public Set<String> extractPermissionsFromRPT(String authorisationToken) {
        Set<String> resourceSetList = new HashSet<>();
        Jwt jwt = JwtHelper.decode(authorisationToken);
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
