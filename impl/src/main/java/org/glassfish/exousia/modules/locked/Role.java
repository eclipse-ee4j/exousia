/*
 * Copyright (c) 2024 Contributors to the Eclipse Foundation.
 * Copyright (c) 1997, 2018 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package org.glassfish.exousia.modules.locked;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author monzillo
 */
public class Role {

    private static final Logger LOG = System.getLogger(Role.class.getName());

    private final String roleName;
    private Permissions permissions;
    private Set<Principal> principals;
    private boolean isAnyAuthenticatedUserRole;

    public Role(String name) {
        roleName = name;
    }

    public String getName() {
        return roleName;
    }

    void addPermission(Permission permission) {
        if (permissions == null) {
            permissions = new Permissions();
        }

        permissions.add(permission);
    }

    void addPermissions(PermissionCollection permissionCollection) {
        if (permissions == null) {
            permissions = new Permissions();
        }

        for (Enumeration<Permission> e = permissionCollection.elements(); e.hasMoreElements();) {
            permissions.add(e.nextElement());
        }
    }

    Permissions getPermissions() {
        return permissions;
    }

    void setPrincipals(Set<Principal> principals) {
        if (principals != null) {
            this.principals = principals;
        }
    }

    boolean implies(Permission permission) {
        if (permissions == null) {
            return false;
        }

        return permissions.implies(permission);
    }

    void determineAnyAuthenticatedUserRole() {
        isAnyAuthenticatedUserRole = false;
        // If no principals are present then any authenticated user is possible
        if (principals == null || principals.isEmpty()) {
            isAnyAuthenticatedUserRole = true;
        }
    }

    boolean isAnyAuthenticatedUserRole() {
        return isAnyAuthenticatedUserRole;
    }

    boolean isPrincipalInRole(Principal principal) {
        if (isAnyAuthenticatedUserRole && (principal != null)) {
            return true;
        }

        if (principals == null) {
            return false;
        }

        return principals.contains(principal);
    }

    boolean arePrincipalsInRole(Principal[] subject) {
        if (subject == null || subject.length == 0) {
            return false;
        }

        if (isAnyAuthenticatedUserRole) {
            return true;
        }

        if (principals == null || principals.isEmpty()) {
            return false;
        }

        LOG.log(Level.DEBUG, () -> "Known principals: "
            + principals.stream().map(Principal::toString).collect(Collectors.joining(", ")));
        for (Principal principal : subject) {
            LOG.log(Level.DEBUG, "Checking principal: {0}", principal);
            if (principals.contains(principal)) {
                return true;
            }
        }
        return false;
    }

    /**
     * NB: Class Overrides equals and hashCode Methods such that 2 Roles are equal simply based on having a common name.
     */
    @Override
    public boolean equals(Object o) {
        Role other = o == null || !(o instanceof Role) ? null : (Role) o;
        return other == null ? false : getName().equals(other.getName());
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 29 * hash + (this.roleName != null ? this.roleName.hashCode() : 0);
        return hash;
    }


    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + roleName + "]";
    }
}
