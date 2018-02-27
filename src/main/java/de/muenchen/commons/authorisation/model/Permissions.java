/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.commons.authorisation.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author roland.werner
 */
public class Permissions implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private Set<String> permissions = new HashSet<>();

    public Set<String> getPermissions() {
        return permissions;
    }
    
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }
    
    public void setPermission(String permission) {
        permissions.add(permission);
    }
    
    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }
    
    public boolean isEmpty() {
        return permissions.isEmpty();
    }


}
