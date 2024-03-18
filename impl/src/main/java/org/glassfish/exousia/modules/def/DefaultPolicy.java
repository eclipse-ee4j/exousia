/*
 * Copyright (c) 2023, 2024 Contributors to the Eclipse Foundation.
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

import static jakarta.security.jacc.PolicyContext.PRINCIPAL_MAPPER;
import static java.util.Collections.list;

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PrincipalMapper;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultPolicy implements Policy {

    private PolicyConfigurationFactory policyConfigurationFactory;
    private PrincipalMapper principalMapper;

    @Override
    public boolean isExcluded(Permission permissionToBeChecked) {
        return isExcluded(
                getPolicyConfigurationFactory().getPolicyConfiguration().getExcludedPermissions(),
                permissionToBeChecked);
    }

    @Override
    public boolean isUnchecked(Permission permissionToBeChecked) {
        return isUnchecked(
                getPolicyConfigurationFactory().getPolicyConfiguration().getUncheckedPermissions(),
                permissionToBeChecked);
    }

    @Override
    public boolean impliesByRole(Permission permissionToBeChecked, Subject subject) {
        if (subject == null) {
            // Without a subject we can't check for roles, so we can shortcut the outcome.
            return false;
        }

        // Get the configuration and mapper instances.
        // Note that these are obtained for the current (application) context ID, and this policy could potentially
        // be used for multiple context IDs. Therefore these objects should not be cached as instance data of this policy.
        PolicyConfiguration policyConfiguration = getPolicyConfigurationFactory().getPolicyConfiguration();
        PrincipalMapper roleMapper = getRoleMapper();

        if (!roleMapper.isAnyAuthenticatedUserRoleMapped() && !subject.getPrincipals().isEmpty()) {
            // The "any authenticated user" role is not mapped, so available to anyone and the current
            // caller is assumed to be authenticated (we assume that an unauthenticated caller doesn't have any
            // principals whatever they are)
            if (hasAccessViaRole(policyConfiguration.getPerRolePermissions(), "**", permissionToBeChecked)) {
                // Access is granted purely based/ on the user being authenticated
                // (the actual roles, if any, the caller has are not important)
                return true;
            }
        }

        // Check to see if access is granted via role.
        // Note that if this returns false it doesn't necessarily mean the permission is not granted.
        // A role can only grant, not take away permissions. Other checks (perhaps another custom policy that embeds us)
        // may still grant the permission.
        return hasAccessViaRoles(
                policyConfiguration.getPerRolePermissions(),
                roleMapper.getMappedRoles(subject),
                permissionToBeChecked);
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
        if (policyConfigurationFactory == null) {
            policyConfigurationFactory = PolicyConfigurationFactory.get();
        }

        return policyConfigurationFactory;
    }

    private PrincipalMapper getRoleMapper() {
        if (principalMapper == null) {
            principalMapper = PolicyContext.get(PRINCIPAL_MAPPER);
        }

        return principalMapper;
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