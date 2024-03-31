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

package org.glassfish.exousia.constraints.transformer;

import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebUserDataPermission;
import jakarta.servlet.annotation.ServletSecurity.TransportGuarantee;

import java.lang.System.Logger;
import java.security.Permission;
import java.security.Permissions;
import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.function.Consumer;

import org.glassfish.exousia.constraints.SecurityConstraint;
import org.glassfish.exousia.constraints.WebResourceCollection;
import org.glassfish.exousia.permissions.JakartaPermissions;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.TRACE;
import static org.glassfish.exousia.constraints.transformer.MethodValue.encodeMethodsToBits;


/**
 * @author Harpreet Singh
 * @author Jean-Francois Arcand
 * @author Ron Monzillo
 * @author Arjan Tijms (refactoring)
 */
public class ConstraintsToPermissionsTransformer {

    private static final Logger LOG = System.getLogger(ConstraintsToPermissionsTransformer.class.getName());

    static final String CLASS_NAME = ConstraintsToPermissionsTransformer.class.getSimpleName();

    /* Changed to order default pattern / below extension */
    private static final int DEFAULT_MAPPING = 0;
    private static final int EXTENSION_MAPPING = 1;
    private static final int PREFIX_MAPPING = 2;
    private static final int EXACT_MAPPING = 3;

    private ConstraintsToPermissionsTransformer() {
    }

    public static JakartaPermissions createResourceAndDataPermissions(Set<String> declaredRoles, boolean isDenyUncoveredHttpMethods, List<SecurityConstraint> securityConstraints) {
        LOG.log(DEBUG, "Jakarta Authorization: constraint translation");

        // Create web resource and data permissions from constraints.

        // This happens in two stages. We'll first create intermediate pattern builders. Then from the pattern builders we
        // create the target permissions.


        // ### Stage 1 ###

        // Generate intermediate patterns first from the constraints.

        Collection<PatternBuilder> patterns = constraintsToIntermediatePatterns(declaredRoles, securityConstraints);


        // ### Stage 2 ###

        // From the intermediate patterns that were created in the previous stage, we now
        // generate the target permissions.

        JakartaPermissions jakartaPermissions = intermediatePatternsToPermissions(patterns, isDenyUncoveredHttpMethods);

        if (LOG.isLoggable(DEBUG)) {
            logPermissions(jakartaPermissions);
        }

        return jakartaPermissions;
    }

    private static Collection<PatternBuilder> constraintsToIntermediatePatterns(Set<String> declaredRoles, List<SecurityConstraint> securityConstraints) {
        LOG.log(TRACE, "constraintsToIntermediatePatterns(declaredRoles={0}, securityConstraints={1})", declaredRoles,
            securityConstraints);
        Map<String, PatternBuilder> patternBuilderMap = new HashMap<>();

        // Seed the map with the default pattern; the default pattern will not be "committed", unless a constraint is
        // defined on "\". This will ensure that a more restrictive constraint can be assigned to it
        patternBuilderMap.put("/", new PatternBuilder("/"));

        // Iterate over security constraints
        for (SecurityConstraint securityConstraint : securityConstraints) {

            LOG.log(TRACE, "Constraint translation: begin parsing security constraint");

            Set<String> constraintRolesAllowed = securityConstraint.getRolesAllowed();
            TransportGuarantee transportGuarantee = securityConstraint.getTransportGuarantee();

            for (WebResourceCollection webResourceCollection : securityConstraint.getWebResourceCollections()) {

                LOG.log(TRACE, "Constraint translation: begin parsing web resource collection");

                // Enumerate over URLPatterns within collection
                for (String urlPattern :  webResourceCollection.getUrlPatterns()) {

                    // FIX TO BE CONFIRMED (will we ever?)
                    urlPattern = urlPattern.replaceAll(":", "%3A");

                    LOG.log(DEBUG, "Constraint translation: process url pattern: {0}", urlPattern);

                    // Determine if pattern is already in map
                    PatternBuilder patternBuilder = patternBuilderMap.get(urlPattern);

                    // Apply new patterns to map
                    if (patternBuilder == null) {
                        patternBuilder = new PatternBuilder(urlPattern);

                        // Iterate over patterns in map
                        for (Entry<String, PatternBuilder> patternBuilderEntry : patternBuilderMap.entrySet()) {

                            String otherUrl = patternBuilderEntry.getKey();

                            int otherUrlType = patternType(otherUrl);
                            switch (patternType(urlPattern)) {

                            // If the new url/pattern is a path-prefix pattern, it must be qualified by every
                            // different (from it) path-prefix pattern (in the map) that is implied by the new
                            // pattern, and every exact pattern (in the map) that is implied by the new URL.
                            //
                            // Also, the new pattern must be added as a qualifier of the default pattern, and every
                            // extension pattern (existing in the map), and of every different path-prefix pattern that
                            // implies the new pattern.
                            //
                            // Note that we know that the new pattern does not exist in the map, thus we know that the
                            // new pattern is different from any existing path prefix pattern.

                            case PREFIX_MAPPING:
                                if ((otherUrlType == PREFIX_MAPPING || otherUrlType == EXACT_MAPPING) && implies(urlPattern, otherUrl)) {
                                    patternBuilder.addQualifier(otherUrl);
                                } else if (otherUrlType == PREFIX_MAPPING && implies(otherUrl, urlPattern)) {
                                    patternBuilderEntry.getValue().addQualifier(urlPattern);
                                } else if (otherUrlType == EXTENSION_MAPPING || otherUrlType == DEFAULT_MAPPING) {
                                    patternBuilderEntry.getValue().addQualifier(urlPattern);
                                }
                                break;

                            // If the new pattern is an extension pattern, it must be qualified by every path-prefix
                            // pattern (in the map), and every exact pattern (in the map) that is implied by
                            // the new pattern.
                            //
                            // Also, it must be added as a qualifier of the default pattern, if it exists in the
                            // map.
                            case EXTENSION_MAPPING:
                                if (otherUrlType == PREFIX_MAPPING || (otherUrlType == EXACT_MAPPING && implies(urlPattern, otherUrl))) {
                                    patternBuilder.addQualifier(otherUrl);
                                } else if (otherUrlType == DEFAULT_MAPPING) {
                                    patternBuilderEntry.getValue().addQualifier(urlPattern);
                                }
                                break;

                            // If the new pattern is the default pattern it must be qualified by every other pattern
                            // in the map.
                            case DEFAULT_MAPPING:
                                if (otherUrlType != DEFAULT_MAPPING) {
                                    patternBuilder.addQualifier(otherUrl);
                                }
                                break;

                            // If the new pattern is an exact pattern, it is not be qualified, but it must be added as
                            // as a qualifier to the default pattern, and to every path-prefix or extension pattern (in
                            // the map) that implies the new pattern.
                            case EXACT_MAPPING:
                                if ((otherUrlType == PREFIX_MAPPING || otherUrlType == EXTENSION_MAPPING) && implies(otherUrl, urlPattern)) {
                                    patternBuilderEntry.getValue().addQualifier(urlPattern);
                                }
                                else if (otherUrlType == DEFAULT_MAPPING) {
                                    patternBuilderEntry.getValue().addQualifier(urlPattern);
                                }
                                break;
                            default:
                                break;
                            }
                        }

                        // Add the new pattern and its pattern spec builder to the map
                        patternBuilderMap.put(urlPattern, patternBuilder);
                    }

                    BitSet methods = encodeMethodsToBits(webResourceCollection.getHttpMethods());

                    BitSet omittedMethods = null;
                    if (methods.isEmpty()) {
                        omittedMethods = encodeMethodsToBits(webResourceCollection.getHttpMethodOmissions());
                    }

                    // Set and commit the method outcomes on the pattern builder
                    //
                    // Note that an empty omitted method set is used to represent
                    // the set of all HTTP methods
                    patternBuilder.setMethodOutcomes(declaredRoles, constraintRolesAllowed, transportGuarantee, methods, omittedMethods);

                    LOG.log(TRACE, "Constraint translation: end processing url pattern: {0}", urlPattern);
                }
            }
        }

        return patternBuilderMap.values();
    }

    private static JakartaPermissions intermediatePatternsToPermissions(Collection<PatternBuilder> patterns, boolean isDenyUncoveredHttpMethods) {
        LOG.log(DEBUG,
            "Constraint capture: begin processing qualified url patterns - uncovered http methods will be {0}",
            (isDenyUncoveredHttpMethods ? "denied" : "permitted"));

        JakartaPermissions jakartaPermissions = new JakartaPermissions();

        for (PatternBuilder patternBuilder : patterns) {
            if (!patternBuilder.isIrrelevantByQualifier()) {

                String urlPatternSpec = patternBuilder.getUrlPatternSpec();
                LOG.log(DEBUG, "Constraint capture: urlPattern: {0}", urlPatternSpec);

                // Handle uncovered methods
                patternBuilder.handleUncovered(isDenyUncoveredHttpMethods);

                // Handle excluded methods - adds resource permissions to the excluded collection
                handleExcluded(jakartaPermissions.getExcluded(), patternBuilder, urlPatternSpec);

                // Handle methods requiring a role - adds resource permissions to the per role collection
                handlePerRole(jakartaPermissions.getPerRole(), patternBuilder, urlPatternSpec);

                // Handle unchecked methods - adds resource permissions to the unchecked collection
                handleUnchecked(jakartaPermissions.getUnchecked(), patternBuilder, urlPatternSpec);

                // Handle transport constraints - adds data permissions to the unchecked collection
                handleConnections(jakartaPermissions.getUnchecked(), patternBuilder, urlPatternSpec);
            }
        }

        return jakartaPermissions;
    }

    private static void handleExcluded(Permissions collection, PatternBuilder patternBuilder, String name) {
        String actions = null;
        BitSet excludedMethods = patternBuilder.getExcludedMethods();

        if (patternBuilder.getOtherConstraint().isExcluded()) {
            BitSet methods = patternBuilder.getMethodSet();
            methods.andNot(excludedMethods);
            if (!methods.isEmpty()) {
                actions = "!" + MethodValue.getActions(methods);
            }
        } else if (!excludedMethods.isEmpty()) {
            actions = MethodValue.getActions(excludedMethods);
        } else {
            return;
        }

        collection.add(new WebResourcePermission(name, actions));
        collection.add(new WebUserDataPermission(name, actions));

        LOG.log(DEBUG, "Constraint capture: adding excluded methods: {0}", actions);
    }

    private static void handlePerRole(Map<String, Permissions> map, PatternBuilder patternBuilder, String urlPatternSpec) {
        Map<String, BitSet> roleMap = patternBuilder.getRoleMap();
        List<String> roleList = null;

        // Handle the roles for the omitted methods
        if (!patternBuilder.getOtherConstraint().isExcluded() && patternBuilder.getOtherConstraint().isAuthConstrained()) {
            roleList = patternBuilder.getOtherConstraint().getRoles();

            for (String roleName : roleList) {
                BitSet methods = patternBuilder.getMethodSet();

                // Reduce omissions for explicit methods granted to role
                BitSet roleMethods = roleMap.get(roleName);
                if (roleMethods != null) {
                    methods.andNot(roleMethods);
                }

                String httpMethodSpec = null;
                if (!methods.isEmpty()) {
                    httpMethodSpec = "!" + MethodValue.getActions(methods);
                }

                addToRoleMap(map, roleName, new WebResourcePermission(urlPatternSpec, httpMethodSpec));
            }
        }

        // Handle explicit methods, skip roles that were handled above
        BitSet methods = patternBuilder.getMethodSet();

        if (!methods.isEmpty()) {
            for (Entry<String, BitSet> roleEntry : roleMap.entrySet()) {
                String roleName = roleEntry.getKey();
                if (roleList == null || !roleList.contains(roleName)) {
                    BitSet roleMethods = roleEntry.getValue();
                    if (!roleMethods.isEmpty()) {
                        addToRoleMap(map, roleName, new WebResourcePermission(urlPatternSpec, MethodValue.getActions(roleMethods)));
                    }
                }
            }
        }
    }

    private static void handleUnchecked(Permissions collection, PatternBuilder patternBuilder, String urlPatternSpec) {
        String httpMethodSpec = null;
        BitSet noAuthMethods = patternBuilder.getNoAuthMethods();

        if (!patternBuilder.getOtherConstraint().isAuthConstrained()) {
            BitSet methods = patternBuilder.getMethodSet();
            methods.andNot(noAuthMethods);
            if (!methods.isEmpty()) {
                httpMethodSpec = "!" + MethodValue.getActions(methods);
            }
        } else if (!noAuthMethods.isEmpty()) {
            httpMethodSpec = MethodValue.getActions(noAuthMethods);
        } else {
            return;
        }

        collection.add(new WebResourcePermission(urlPatternSpec, httpMethodSpec));

        LOG.log(DEBUG, "Constraint capture: adding unchecked (for authorization) methods: {0}", httpMethodSpec);
    }

    private static void handleConnections(Permissions permissions, PatternBuilder patternBuilder, String name) {
        BitSet allConnectMethods = null;
        boolean allConnectAtOther = patternBuilder.getOtherConstraint().isConnectAllowed(ConstraintValue.connectTypeNone);

        for (int i = 0; i < ConstraintValue.connectKeys.length; i++) {

            String actions = null;
            String transport = ConstraintValue.connectKeys[i];

            BitSet connectMethods = patternBuilder.getConnectMap(1 << i);
            if (i == 0) {
                allConnectMethods = connectMethods;
            } else {

                // If connect type protected, remove methods that accept any connect
                connectMethods.andNot(allConnectMethods);
            }

            if (patternBuilder.getOtherConstraint().isConnectAllowed(1 << i)) {
                if (i != 0 && allConnectAtOther) {

                    // If all connect allowed at other

                    if (connectMethods.isEmpty()) {

                        // Skip, if remainder is empty, because methods that accept any connect were handled at i==0.
                        continue;
                    }

                    // Construct actions using methods with specific connection requirements
                    actions = MethodValue.getActions(connectMethods);
                } else {
                    BitSet methods = patternBuilder.getMethodSet();
                    methods.andNot(connectMethods);
                    if (!methods.isEmpty()) {
                        actions = "!" + MethodValue.getActions(methods);
                    }
                }
            } else if (!connectMethods.isEmpty()) {
                actions = MethodValue.getActions(connectMethods);
            } else {
                continue;
            }

            actions = (actions == null) ? "" : actions;
            String combinedActions = actions + ":" + transport;

            permissions.add(new WebUserDataPermission(name, combinedActions));

            LOG.log(DEBUG,
                "Constraint capture: adding methods that accept connections with protection: {0} methods: {1}",
                transport, actions);
        }
    }

    static int patternType(Object urlPattern) {
        String pattern = urlPattern.toString();

        if (pattern.startsWith("*.")) {
            return EXTENSION_MAPPING;
        }

        if (pattern.startsWith("/") && pattern.endsWith("/*")) {
            return PREFIX_MAPPING;
        }

        if (pattern.equals("/")) {
            return DEFAULT_MAPPING;
        }

        return EXACT_MAPPING;
    }

    static boolean implies(String pattern, String path) {

        // Check for exact match
        if (pattern.equals(path)) {
            return true;
        }

        // Check for path prefix matching
        if (pattern.startsWith("/") && pattern.endsWith("/*")) {
            pattern = pattern.substring(0, pattern.length() - 2);

            int length = pattern.length();

            if (length == 0) {
                return true; // "/*" is the same as "/"
            }

            return path.startsWith(pattern) && (path.length() == length || path.substring(length).startsWith("/"));
        }

        // Check for suffix matching
        if (pattern.startsWith("*.")) {
            int slash = path.lastIndexOf('/');
            int period = path.lastIndexOf('.');
            if ((slash >= 0) && (period > slash) && path.endsWith(pattern.substring(1))) {
                return true;
            }

            return false;
        }

        // Check for universal mapping
        if (pattern.equals("/")) {
            return true;
        }

        return false;
    }

    private static void addToRoleMap(Map<String, Permissions> roleMap, String roleName, Permission permission) {
        roleMap.computeIfAbsent(roleName, e -> new Permissions())
               .add(permission);

        LOG.log(DEBUG, "Constraint capture: adding methods to role: {0} methods: {1}", roleName, permission.getActions());
    }

    private static void logPermissions(JakartaPermissions permissions) {
        final StringBuilder message = new StringBuilder();
        message.append("Resolved permissions:");
        message.append("\n  Exclusions:");
        permissions.getExcluded().elementsAsStream().forEach(toMessageElement(message));
        message.append("\n  Unchecked:");
        permissions.getUnchecked().elementsAsStream().forEach(toMessageElement(message));
        message.append("\n  Checked:");
        for (Entry<String, Permissions> roleEntry : permissions.getPerRole().entrySet()) {
            message.append("\n    Role ").append(roleEntry.getKey()).append(':');
            roleEntry.getValue().elementsAsStream().forEach(toMessageElement(message));
        }

        LOG.log(DEBUG, message);
    }

    private static Consumer<? super Permission> toMessageElement(final StringBuilder message) {
        return permission -> message.append("\n    type: ").append(permissionType(permission)).append(", name: ")
            .append(permission.getName()).append(", actions: ").append(permission.getActions());
    }

    private static String permissionType(Permission permission) {
        return permission instanceof WebResourcePermission ? "WRP  " : "WUDP ";
    }
}
