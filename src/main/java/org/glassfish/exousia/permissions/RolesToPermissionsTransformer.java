/*
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

package org.glassfish.exousia.permissions;

import static java.util.logging.Level.FINE;

import java.security.Permission;
import java.security.Permissions;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.glassfish.exousia.constraints.transformer.ConstraintsToPermissionsTransformer;
import org.glassfish.exousia.mapping.SecurityRoleRef;

import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.WebRoleRefPermission;

/**
 * @author Harpreet Singh
 * @author Jean-Francois Arcand
 * @author Ron Monzillo
 * @author Arjan Tijms (refactoring)
 */
public class RolesToPermissionsTransformer {
    static final Logger logger = Logger.getLogger(ConstraintsToPermissionsTransformer.class.getName());

    public static final String ANY_AUTHENTICATED_CALLER_ROLE = "**";

    private static final String CLASS_NAME = ConstraintsToPermissionsTransformer.class.getSimpleName();

    public static Map<String, Permissions> createWebRoleRefPermission(Set<String> declaredRoles, Map<String, List<SecurityRoleRef>> servletRoleMappings) throws PolicyContextException {
        if (logger.isLoggable(FINE)) {
            logger.entering(CLASS_NAME, "createWebRoleRefPermission");
            logger.log(FINE, "Jakarta Authorization: role-reference translation: Processing WebRoleRefPermission");
        }

        Map<String, Permissions> roleMap = new HashMap<String, Permissions>();


        List<String> servletScopedRoleNames = new ArrayList<>();


        boolean rolesetContainsAnyAuthUserRole = declaredRoles.contains(ANY_AUTHENTICATED_CALLER_ROLE);

        // Look at local roles per Servlet

        for (Map.Entry<String, List<SecurityRoleRef>> servletEntry : servletRoleMappings.entrySet()) {
            addPermissionsForRoleRefRoles(servletEntry, servletScopedRoleNames, roleMap);

            logger.fine("Jakarta Authorization: role-reference translation: Going through the list of roles not present in RoleRef elements and creating WebRoleRefPermissions ");

            // We insert identity mapped (one to one) roles for all declared roles that do not have a servlet local role (role refs) mapping.
            // Role refs are an artifact from the "reffing days" in J2EE and not commonly used anymore.
            addPermissionsForNonRoleRefRoles(declaredRoles, servletScopedRoleNames, servletEntry.getKey(), roleMap);

            // JACC MR8 add WebRoleRefPermission for the any authenticated user role '**'
            if ((!servletScopedRoleNames.contains(ANY_AUTHENTICATED_CALLER_ROLE)) && !rolesetContainsAnyAuthUserRole) {
                addAnyAuthenticatedUserRoleRef(roleMap, servletEntry.getKey());
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
        addGlobalPermissionsForAllRoles(declaredRoles, roleMap);

        // JACC MR8 add WebRoleRefPermission for the any authenticated user role '**'
        if (!rolesetContainsAnyAuthUserRole) {
            addAnyAuthenticatedUserRoleRef(roleMap, "");
        }

        if (logger.isLoggable(FINE)) {
            logger.exiting(CLASS_NAME, "createWebRoleRefPermission");
        }

        return roleMap;
    }

    /**
     * Adds <code>WebRoleRefPermission</code>s to the <code>Map</code> based on the passed in collection of declared roles.
     *
     * @param declaredRoles all declared roles
     * @param roleMap map to which permissions will be added
     */
    private static void addGlobalPermissionsForAllRoles(Collection<String> declaredRoles, Map<String, Permissions> roleMap) {
        for (String role : declaredRoles) {
            if (logger.isLoggable(FINE)) {
                logger.fine("Jakarta Authorization: role-reference translation: Looking at Role =  " + role);
            }

            addToRoleMap(roleMap, role, new WebRoleRefPermission("", role));

            if (logger.isLoggable(FINE)) {
                logger.fine("Jakarta Authorization: role-reference translation: RoleRef  = " + role + " is added for jsp's that can't be mapped to servlets");
                logger.fine("Jakarta Authorization: role-reference translation: Permission added for above role-ref =" + role + " " + "");
            }
        }
    }

    private static void addPermissionsForRoleRefRoles(Map.Entry<String, List<SecurityRoleRef>> servletEntry, Collection<String> servletScopedRoleNames, Map<String, Permissions> roleMap) {
        for (SecurityRoleRef securityRoleRef : servletEntry.getValue()) {

                // The name of a local role, which is a role scoped to a single Servlet
                servletScopedRoleNames.add(securityRoleRef.getRoleName());

                // The name of the global role, which is the role a local role is mapped to (aka is linked to)
                String globalRole = securityRoleRef.getRoleLink();

                // Add the role reference to the outcome
                addToRoleMap(roleMap,
                    globalRole,
                    new WebRoleRefPermission(servletEntry.getKey(), securityRoleRef.getRoleName()));

                if (logger.isLoggable(FINE)) {
                    logger.fine(
                        "Jakarta Authorization: role-reference translation: " +
                         "WebRoleRefPermission created with name (servlet-name) = " + servletEntry.getKey() +
                         " and action (role-name tag) = " + securityRoleRef.getRoleName() +
                         " added to role (role-link tag) = " + globalRole);
                }
        }
    }

    /**
     * @param declaredRoles all declared roles
     * @param roleRefRoles roles mapped to global roles
     * @param servletName name of the servlet for which permissions are added to the map
     * @param roleMap map to which permissions will be added
     */
    private static void addPermissionsForNonRoleRefRoles(Collection<String> declaredRoles, Collection<String> roleRefRoles, String servletName, Map<String, Permissions> roleMap) {
        for (String role : declaredRoles) {
            if (logger.isLoggable(FINE)) {
                logger.fine("Jakarta Authorization: role-reference translation: Looking at Role =  " + role);
            }

            // For all roles for which no role reference role was created, create an identity mapping from the global roles.
            if (!roleRefRoles.contains(role)) {

                addToRoleMap(roleMap, role, new WebRoleRefPermission(servletName, role));

                if (logger.isLoggable(FINE)) {
                    logger.fine("Jakarta Authorization: role-reference translation: RoleRef  = " + role + " is added for servlet-resource = " + servletName);
                    logger.fine("Jakarta Authorization: role-reference translation: Permission added for above role-ref =" + servletName + " " + role);
                }
            }
        }
    }

    /**
     * JACC MR8 add WebRoleRefPermission for the any authenticated user role '**'
     */
    private static void addAnyAuthenticatedUserRoleRef(Map<String, Permissions> roleMap, String name) throws PolicyContextException {
        addToRoleMap(roleMap, ANY_AUTHENTICATED_CALLER_ROLE, new WebRoleRefPermission(name, ANY_AUTHENTICATED_CALLER_ROLE));

        if (logger.isLoggable(FINE)) {
            logger.fine("Jakarta Authorization: any authenticated user role-reference translation: Permission added for role-ref =" + name + " " + ANY_AUTHENTICATED_CALLER_ROLE);
        }
    }

    private static void addToRoleMap(Map<String, Permissions> roleMap, String role, Permission permission) {
        roleMap.computeIfAbsent(role, e -> new Permissions())
               .add(permission);
    }
}
