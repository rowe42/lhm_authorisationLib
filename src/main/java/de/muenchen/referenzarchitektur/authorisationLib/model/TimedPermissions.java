/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.referenzarchitektur.authorisationLib.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author roland.werner
 */
public class TimedPermissions {

    private LocalDateTime refreshDate;
    private Set<String> permissions = new HashSet<>();

    public LocalDateTime getRefreshDate() {
        return refreshDate;
    }

    public void setRefreshDate(LocalDateTime refreshDate) {
        this.refreshDate = refreshDate;
    }

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


}
