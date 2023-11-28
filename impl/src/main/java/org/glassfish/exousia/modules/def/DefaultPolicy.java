/*
 * Copyright (c) 2023 Contributors to the Eclipse Foundation.
 * Copyright (c) 2019, 2021 OmniFaces. All rights reserved.
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
package org.glassfish.exousia.modules.def;

import static java.util.Collections.list;

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PrincipalMapper;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Principal;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultPolicy implements Policy {

    @Override
    public boolean implies(Permission permissionToBeChecked, Subject subject) {
        PolicyConfiguration policyConfiguration = getPolicyConfigurationFactory().getPolicyConfiguration();
        PrincipalMapper roleMapper = getRoleMapper();

        if (isExcluded(policyConfiguration.getExcludedPermissions(), permissionToBeChecked)) {
            // Excluded permissions cannot be accessed by anyone
            return false;
        }

        if (isUnchecked(policyConfiguration.getUncheckedPermissions(), permissionToBeChecked)) {
            // Unchecked permissions are free to be accessed by everyone
            return true;
        }

        if (subject == null) {
            return false;
        }

        Set<Principal> currentUserPrincipals = subject.getPrincipals();

        if (!roleMapper.isAnyAuthenticatedUserRoleMapped() && !currentUserPrincipals.isEmpty()) {
            // The "any authenticated user" role is not mapped, so available to anyone and the current
            // user is assumed to be authenticated (we assume that an unauthenticated user doesn't have any
            // principals whatever they are)
            if (hasAccessViaRole(policyConfiguration.getPerRolePermissions(), "**", permissionToBeChecked)) {
                // Access is granted purely based/ on the user being authenticated
                // (the actual roles, if any, the user has it not important)
                return true;
            }
        }

        if (hasAccessViaRoles(policyConfiguration.getPerRolePermissions(), roleMapper.getMappedRoles(subject),
                permissionToBeChecked)) {
            // Access is granted via role. Note that if this returns false/ it doesn't mean the permission is not granted.
            // A role can only grant, not take away permissions.
            return true;
        }

        return false;
    }

    @Override
    public PermissionCollection getPermissionCollection(Subject subject) {
        Permissions permissions = new Permissions();

        PolicyConfiguration policyConfiguration = getPolicyConfigurationFactory().getPolicyConfiguration();
        PrincipalMapper roleMapper = getRoleMapper();

        PermissionCollection excludedPermissions = policyConfiguration.getExcludedPermissions();

        // Get all unchecked permissions
        collectPermissions(policyConfiguration.getUncheckedPermissions(), permissions, excludedPermissions);

        // Next get the permissions for each role
        // *that the current user has*
        //
        Map<String, PermissionCollection> perRolePermissions = policyConfiguration.getPerRolePermissions();

        for (String role : roleMapper.getMappedRoles(subject)) {
            if (perRolePermissions.containsKey(role)) {
                collectPermissions(perRolePermissions.get(role), permissions, excludedPermissions);
            }
        }

        return permissions;
    }


    // ### Private methods

    private PolicyConfigurationFactory getPolicyConfigurationFactory() {
        try {
            return PolicyConfigurationFactory.getPolicyConfigurationFactory();
        } catch (ClassNotFoundException | PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    private PrincipalMapper getRoleMapper() {
        try {
            return PolicyContext.getContext(PolicyContext.PRINCIPAL_MAPPER);
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean isExcluded(PermissionCollection excludedPermissions, Permission permission) {
        if (excludedPermissions.implies(permission)) {
            return true;
        }

        for (Permission excludedPermission : list(excludedPermissions.elements())) {
            if (permission.implies(excludedPermission)) {
                return true;
            }
        }

        return false;
    }

    private boolean isUnchecked(PermissionCollection uncheckedPermissions, Permission permission) {
        return uncheckedPermissions.implies(permission);
    }

    private boolean hasAccessViaRoles(Map<String, PermissionCollection> perRolePermissions, Set<String> roles, Permission permission) {
        for (String role : roles) {
            if (hasAccessViaRole(perRolePermissions, role, permission)) {
                return true;
            }
        }

        return false;
    }

    private boolean hasAccessViaRole(Map<String, PermissionCollection> perRolePermissions, String role, Permission permission) {
        return perRolePermissions.containsKey(role) && perRolePermissions.get(role).implies(permission);
    }

    /**
     * Copies permissions from a source into a target skipping any permission that's excluded.
     *
     * @param sourcePermissions
     * @param targetPermissions
     * @param excludedPermissions
     */
    private void collectPermissions(PermissionCollection sourcePermissions, PermissionCollection targetPermissions,
            PermissionCollection excludedPermissions) {

        boolean hasExcludedPermissions = excludedPermissions.elements().hasMoreElements();

        for (Permission permission : list(sourcePermissions.elements())) {
            if (!hasExcludedPermissions || !isExcluded(excludedPermissions, permission)) {
                targetPermissions.add(permission);
            }
        }
    }

}