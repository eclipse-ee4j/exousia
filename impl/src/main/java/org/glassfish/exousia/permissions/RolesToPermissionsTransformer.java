/*
 * Copyright (c) 2024 Contributors to the Eclipse Foundation.
 * Copyright (c) 1997, 2021 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.exousia.permissions;

import jakarta.security.jacc.EJBRoleRefPermission;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.WebRoleRefPermission;

import java.lang.System.Logger;
import java.security.Permission;
import java.security.Permissions;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;

import org.glassfish.exousia.constraints.transformer.ConstraintsToPermissionsTransformer;
import org.glassfish.exousia.mapping.SecurityRoleRef;

import static java.lang.System.Logger.Level.DEBUG;


/**
 * @author Harpreet Singh
 * @author Jean-Francois Arcand
 * @author Ron Monzillo
 * @author Arjan Tijms
 */
public class RolesToPermissionsTransformer {
    private static final Logger LOG = System.getLogger(RolesToPermissionsTransformer.class.getName());

    public static final String ANY_AUTHENTICATED_CALLER_ROLE = "**";

    private static final String CLASS_NAME = ConstraintsToPermissionsTransformer.class.getSimpleName();

    private static final BiFunction<String, String, Permission> CREATE_BEAN_REF = EJBRoleRefPermission::new;
    private static final BiFunction<String, String, Permission> CREATE_WEB_REF = WebRoleRefPermission::new;

    public static JakartaPermissions createWebRoleRefPermission(Set<String> declaredRoles,
        Map<String, List<SecurityRoleRef>> servletRoleMappings) throws PolicyContextException {
        LOG.log(DEBUG, "The role-reference translation: Processing WebRoleRefPermission for roles {0}", declaredRoles);

        JakartaPermissions jakartaPermissions = new JakartaPermissions();

        List<String> servletScopedRoleNames = new ArrayList<>();

        boolean rolesetContainsAnyAuthUserRole = declaredRoles.contains(ANY_AUTHENTICATED_CALLER_ROLE);

        // Look at local roles per Servlet

        for (Map.Entry<String, List<SecurityRoleRef>> servletEntry : servletRoleMappings.entrySet()) {
            addPermissionsForRoleRefRoles(CREATE_WEB_REF, servletEntry, servletScopedRoleNames, jakartaPermissions.getPerRole());

            LOG.log(DEBUG, "role-reference translation: Going through the list of roles not present in RoleRef elements and creating WebRoleRefPermissions ");

            // We insert identity mapped (one to one) roles for all declared roles that do not have a servlet local role (role refs) mapping.
            // Role refs are an artifact from the "reffing days" in J2EE and not commonly used anymore.
            addPermissionsForNonRoleRefRoles(CREATE_WEB_REF, declaredRoles, servletScopedRoleNames, servletEntry.getKey(), jakartaPermissions.getPerRole());

            // JACC MR8 add WebRoleRefPermission for the any authenticated user role '**'
            if ((!servletScopedRoleNames.contains(ANY_AUTHENTICATED_CALLER_ROLE)) && !rolesetContainsAnyAuthUserRole) {
                addAnyAuthenticatedUserRoleRef(CREATE_WEB_REF, jakartaPermissions.getPerRole(), servletEntry.getKey());
            }
        }

        // Look at roles global for the application.

        // For every security role in the web application add a WebRoleRefPermission to the corresponding role. The name of all
        // such permissions shall be the empty string, and the actions of each permission shall be the corresponding role name.

        // When checking a WebRoleRefPermission from a JSP not mapped to a servlet, use a permission with the empty string as
        // its name and with the argument to isUserInRole as its actions
        //
        // Note, this creates application scoped roles (global roles), and Servlet scoped roles (local roles)
        //
        // See also S1AS8PE 4966609
        addGlobalPermissionsForAllRoles(declaredRoles, jakartaPermissions.getPerRole());

        // JACC MR8 add WebRoleRefPermission for the any authenticated user role '**'
        if (!rolesetContainsAnyAuthUserRole) {
            addAnyAuthenticatedUserRoleRef(CREATE_WEB_REF, jakartaPermissions.getPerRole(), "");
        }

        return jakartaPermissions;
    }

    public static JakartaPermissions createEnterpriseBeansRoleRefPermission(Set<String> declaredRoles, Map<String, List<SecurityRoleRef>> beanRoleMappings) throws PolicyContextException {
        LOG.log(DEBUG, "The role-reference translation: Processing EjbRoleRefPermission for roles {0}", declaredRoles);

        JakartaPermissions jakartaPermissions = new JakartaPermissions();

        List<String> beanScopedRoleNames = new ArrayList<>();

        boolean rolesetContainsAnyAuthUserRole = declaredRoles.contains(ANY_AUTHENTICATED_CALLER_ROLE);

        // Look at local roles per Bean

        for (Map.Entry<String, List<SecurityRoleRef>> beanEntry : beanRoleMappings.entrySet()) {
            addPermissionsForRoleRefRoles(CREATE_BEAN_REF, beanEntry, beanScopedRoleNames, jakartaPermissions.getPerRole());

            LOG.log(DEBUG, "Going through the list of roles not present in RoleRef elements and creating EjbRoleRefPermissions.");

            // We insert identity mapped (one to one) roles for all declared roles that do not have a bean local role (role refs) mapping.
            // Role refs are an artifact from the "reffing days" in J2EE and not commonly used anymore.
            addPermissionsForNonRoleRefRoles(CREATE_BEAN_REF, declaredRoles, beanScopedRoleNames, beanEntry.getKey(), jakartaPermissions.getPerRole());

            // JACC MR8 add WebRoleRefPermission for the any authenticated user role '**'
            if ((!beanScopedRoleNames.contains(ANY_AUTHENTICATED_CALLER_ROLE)) && !rolesetContainsAnyAuthUserRole) {
                addAnyAuthenticatedUserRoleRef(CREATE_BEAN_REF, jakartaPermissions.getPerRole(), beanEntry.getKey());
            }
        }

        return jakartaPermissions;
    }


    /**
     * Adds <code>WebRoleRefPermission</code>s to the <code>Map</code> based on the passed in collection of declared roles.
     *
     * @param declaredRoles all declared roles
     * @param roleMap map to which permissions will be added
     */
    private static void addGlobalPermissionsForAllRoles(Collection<String> declaredRoles, Map<String, Permissions> roleMap) {
        for (String role : declaredRoles) {
            addToRoleMap(roleMap, role, new WebRoleRefPermission("", role));
            LOG.log(DEBUG, "The role-reference translation: RoleRef {0} is added for jsp's that can't be"
                + " mapped to servlets. Permission added for above role-ref = {0}", role);
        }
    }

    private static void addPermissionsForRoleRefRoles(BiFunction<String, String, Permission> createComponent, Map.Entry<String, List<SecurityRoleRef>> roleEntry, Collection<String> componentScopedRoleNames, Map<String, Permissions> roleMap) {
        for (SecurityRoleRef securityRoleRef : roleEntry.getValue()) {

            // The name of a local role, which is a role scoped to a single component (such as a Servlet or Enterprise Bean)
            componentScopedRoleNames.add(securityRoleRef.getRoleName());

            // The name of the global role, which is the role a local role is mapped to (aka is linked to)
            String globalRole = securityRoleRef.getRoleLink();

            // Add the role reference to the outcome
            addToRoleMap(roleMap,
                globalRole,
                createComponent.apply(roleEntry.getKey(), securityRoleRef.getRoleName()));

            LOG.log(DEBUG,
                "The role-reference translation: RoleRefPermission created with"
                    + " name = {0} and action = {1} added to role = {2}",
                roleEntry.getKey(), securityRoleRef.getRoleName(), globalRole);
        }
    }

    /**
     * @param declaredRoles all declared roles
     * @param roleRefRoles roles mapped to global roles
     * @param componentName name of the servlet for which permissions are added to the map
     * @param roleMap map to which permissions will be added
     */
    private static void addPermissionsForNonRoleRefRoles(BiFunction<String, String, Permission> createComponent,
        Collection<String> declaredRoles, Collection<String> roleRefRoles, String componentName,
        Map<String, Permissions> roleMap) {
        for (String role : declaredRoles) {
            LOG.log(DEBUG, "The role-reference translation: Looking at Role = {0}", role);

            // For all roles for which no role reference role was created, create an identity mapping from the global roles.
            if (!roleRefRoles.contains(role)) {

                addToRoleMap(roleMap, role, createComponent.apply(componentName, role));

                LOG.log(DEBUG, "The role-reference translation: RoleRef = {0} is added for = {1}."
                    + " Permission added for above role-ref = {1} {0}", role, componentName);
            }
        }
    }

    /**
     * Jakarta Authorization add WebRoleRefPermission for the any authenticated user role '**'
     */
    private static void addAnyAuthenticatedUserRoleRef(BiFunction<String, String, Permission> createComponent, Map<String, Permissions> roleMap, String name) throws PolicyContextException {
        addToRoleMap(roleMap, ANY_AUTHENTICATED_CALLER_ROLE, createComponent.apply(name, ANY_AUTHENTICATED_CALLER_ROLE));

        LOG.log(DEBUG, "Any authenticated user role-reference translation: Permission added for role-ref = {0} {1}",
            name, ANY_AUTHENTICATED_CALLER_ROLE);
    }

    private static void addToRoleMap(Map<String, Permissions> roleMap, String role, Permission permission) {
        roleMap.computeIfAbsent(role, e -> new Permissions())
               .add(permission);
    }
}
