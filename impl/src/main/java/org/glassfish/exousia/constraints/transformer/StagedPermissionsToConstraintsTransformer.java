/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
package org.glassfish.exousia.constraints.transformer;

import jakarta.security.jacc.WebResourcePermission;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.glassfish.exousia.constraints.SecurityConstraint;
import org.glassfish.exousia.constraints.WebResourceCollection;
import org.glassfish.exousia.permissions.JakartaPermissions;

import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.NONE;
import static java.util.Collections.list;

public final class StagedPermissionsToConstraintsTransformer {

    private StagedPermissionsToConstraintsTransformer() {
    }

    public static StagedPermissionToConstraintResult transform(JakartaPermissions stagedPermissions) {
        List<SecurityConstraint> constraints = new ArrayList<>();
        JakartaPermissions passThrough = new JakartaPermissions();

        if (stagedPermissions != null) {
            convertExcluded(
                stagedPermissions.getExcluded(),
                constraints,
                passThrough.getExcluded());

            convertUnchecked(
                stagedPermissions.getUnchecked(),
                constraints,
                passThrough.getUnchecked());

            convertPerRole(
                stagedPermissions.getPerRole(),
                constraints,
                passThrough.getPerRole());
        }

        return new StagedPermissionToConstraintResult(
            List.copyOf(constraints),
            passThrough);
    }

    private static void convertExcluded(PermissionCollection source, List<SecurityConstraint> constraints, Permissions passThrough) {
        for (Permission permission : list(source.elements())) {
            if (permission instanceof WebResourcePermission webResourcePermission) {
                constraints.add(toExcludedConstraint(webResourcePermission));
            } else {
                passThrough.add(permission);
            }
        }
    }

    private static void convertUnchecked(PermissionCollection source, List<SecurityConstraint> constraints, Permissions passThrough) {
        for (Permission permission : list(source.elements())) {
            if (permission instanceof WebResourcePermission webResourcePermission) {
                constraints.add(toUncheckedConstraint(webResourcePermission));
            } else {
                passThrough.add(permission);
            }
        }
    }

    private static void convertPerRole(Map<String, Permissions> source, List<SecurityConstraint> constraints, Map<String, Permissions> passThrough) {
        Map<PermissionKey, Set<String>> rolesByPermission = new LinkedHashMap<>();

        for (Map.Entry<String, Permissions> roleEntry : source.entrySet()) {
            String role = roleEntry.getKey();

            for (Permission permission : list(roleEntry.getValue().elements())) {
                if (permission instanceof WebResourcePermission webResourcePermission) {
                    PermissionKey key = PermissionKey.of(webResourcePermission);

                    rolesByPermission.computeIfAbsent(key, ignored -> new LinkedHashSet<>()).add(role);
                } else {
                    passThrough.computeIfAbsent(role, ignored -> new Permissions()).add(permission);
                }
            }
        }

        for (Map.Entry<PermissionKey, Set<String>> entry : rolesByPermission.entrySet()) {
            constraints.add(toRoleConstraint(entry.getKey(), entry.getValue()));
        }
    }

    private static SecurityConstraint toExcludedConstraint(
            WebResourcePermission permission) {

        return toConstraint(
            requireSimpleUrlPattern(permission.getName()),
            MethodSelector.fromActions(permission.getActions()),
            Set.of());
    }

    private static SecurityConstraint toUncheckedConstraint(
            WebResourcePermission permission) {

        return toConstraint(
            requireSimpleUrlPattern(permission.getName()),
            MethodSelector.fromActions(permission.getActions()),
            null);
    }

    private static SecurityConstraint toRoleConstraint(
            PermissionKey permissionKey,
            Set<String> roles) {

        return toConstraint(
            requireSimpleUrlPattern(permissionKey.name()),
            MethodSelector.fromActions(permissionKey.actions()),
            Set.copyOf(roles));
    }

    /**
     * rolesAllowed interpretation used here:
     *
     * null      -> no auth-constraint, unchecked
     * empty     -> auth-constraint with no roles, excluded
     * non-empty -> auth-constraint with roles
     */
    private static SecurityConstraint toConstraint(String urlPattern, MethodSelector methodSelector, Set<String> rolesAllowed) {
        WebResourceCollection webResourceCollection =
                new WebResourceCollection(
                        Set.of(urlPattern),
                        methodSelector.httpMethods(),
                        methodSelector.httpMethodOmissions());

        return
            new SecurityConstraint(List.of(webResourceCollection), rolesAllowed, NONE);

    }

    private static String requireSimpleUrlPattern(String name) {
        if (name == null) {
            throw new IllegalArgumentException(
                "Staged WebResourcePermission name must not be null");
        }

        if (name.indexOf(':') >= 0) {
            throw new IllegalArgumentException(
                "Staged WebResourcePermission must not already be a qualified URLPatternSpec: "
                    + name);
        }

        if (name.indexOf('{') >= 0 || name.indexOf('}') >= 0) {
            throw new IllegalArgumentException(
                "JAX-RS template paths are not supported in this temporary bridge: "
                    + name);
        }

        return name;
    }

    private record PermissionKey(
            String name,
            String actions) {

        static PermissionKey of(WebResourcePermission permission) {
            return new PermissionKey(
                permission.getName(),
                normalizeActions(permission.getActions()));
        }

        private static String normalizeActions(String actions) {
            if (actions == null || actions.isBlank()) {
                return null;
            }

            return actions.trim();
        }
    }

    private record MethodSelector(Set<String> httpMethods, Set<String> httpMethodOmissions) {

        static MethodSelector fromActions(String actions) {
            if (actions == null || actions.isBlank()) {
                // Empty httpMethods + empty httpMethodOmissions means all methods.
                return new MethodSelector(Set.of(), Set.of());
            }

            String normalizedActions = actions.trim();

            if (normalizedActions.startsWith("!")) {
                return new MethodSelector(Set.of(), splitMethods(normalizedActions.substring(1)));
            }

            return new MethodSelector(splitMethods(normalizedActions), Set.of());
        }

        private static Set<String> splitMethods(String actions) {
            if (actions == null || actions.isBlank()) {
                return Set.of();
            }

            Set<String> methods = new LinkedHashSet<>();

            for (String action : actions.split(",")) {
                String method = action.trim();

                if (!method.isEmpty()) {
                    methods.add(method);
                }
            }

            return Set.copyOf(methods);
        }
    }

}