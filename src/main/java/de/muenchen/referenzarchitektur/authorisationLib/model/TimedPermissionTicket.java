/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.referenzarchitektur.authorisationLib.model;

import java.time.LocalDateTime;

/**
 *
 * @author roland.werner
 */
public class TimedPermissionTicket {
    private LocalDateTime refreshDate;

    public LocalDateTime getRefreshDate() {
        return refreshDate;
    }

    public void setRefreshDate(LocalDateTime refreshDate) {
        this.refreshDate = refreshDate;
    }

    public String getPermissionTicket() {
        return permissionTicket;
    }

    public void setPermissionTicket(String permissionTicket) {
        this.permissionTicket = permissionTicket;
    }
    private String permissionTicket;
}
