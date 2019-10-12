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

package org.omnifaces.exousia.constraints.transformer;

import static java.util.Collections.list;
import static java.util.logging.Level.FINE;
import static org.omnifaces.exousia.constraints.transformer.MethodValue.encodeMethodsToBits;

import java.security.Permission;
import java.security.Permissions;
import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebResourcePermission;
import javax.security.jacc.WebUserDataPermission;
import javax.servlet.annotation.ServletSecurity.TransportGuarantee;

import org.omnifaces.exousia.constraints.SecurityConstraint;
import org.omnifaces.exousia.constraints.WebResourceCollection;
import org.omnifaces.exousia.permissions.JakartaPermissions;


/**
 * @author Harpreet Singh
 * @author Jean-Francois Arcand
 * @author Ron Monzillo
 * @author Arjan Tijms (refactoring)
 */
public class ConstraintsToPermissionsTransformer {

    static final Logger logger = Logger.getLogger(ConstraintsToPermissionsTransformer.class.getName());
    
    static final String CLASS_NAME = ConstraintsToPermissionsTransformer.class.getSimpleName();

    /* Changed to order default pattern / below extension */
    private static final int DEFAULT_MAPPING = 0;
    private static final int EXTENSION_MAPPING = 1;
    private static final int PREFIX_MAPPING = 2;
    private static final int EXACT_MAPPING = 3;

    private ConstraintsToPermissionsTransformer() {
    }

    public static JakartaPermissions createResourceAndDataPermissions(Set<String> declaredRoles, boolean isDenyUncoveredHttpMethods, List<SecurityConstraint> securityConstraints) {
        if (logger.isLoggable(FINE)) {
            logger.entering(ConstraintsToPermissionsTransformer.class.getSimpleName(), "createResourceAndDataPermissions");
            logger.log(FINE, "Jakarta Authorization: constraint translation");
        }
        
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

        
        // ### Log until there's nothing left to log ###

        logExcludedUncheckedPermissionsWritten(jakartaPermissions.getExcluded(), jakartaPermissions.getUnchecked());

        // Log the generated per role permission
        for (Entry<String, Permissions> roleEntry : jakartaPermissions.getPerRole().entrySet()) {
            logPerRolePermissionsWritten(roleEntry.getKey(), roleEntry.getValue());
        }

        if (logger.isLoggable(FINE)) {
            logger.exiting(CLASS_NAME, "processConstraints");
        }
        
        return jakartaPermissions;
    }

    private static Collection<PatternBuilder> constraintsToIntermediatePatterns(Set<String> declaredRoles, List<SecurityConstraint> securityConstraints) {
        if (logger.isLoggable(FINE)) {
            logger.entering(CLASS_NAME, "parseConstraints");
        }

        Map<String, PatternBuilder> patternBuilderMap = new HashMap<>();

        // Seed the map with the default pattern; the default pattern will not be "committed", unless a constraint is
        // defined on "\". This will ensure that a more restrictive constraint can be assigned to it
        patternBuilderMap.put("/", new PatternBuilder("/"));

        // Iterate over security constraints
        for (SecurityConstraint securityConstraint : securityConstraints) {

            logger.fine("Jakarta Authorization: constraint translation: begin parsing security constraint");

            Set<String> constraintRolesAllowed = securityConstraint.getRolesAllowed();
            TransportGuarantee transportGuarantee = securityConstraint.getTransportGuarantee();
            
            for (WebResourceCollection webResourceCollection : securityConstraint.getWebResourceCollections()) {

                logger.fine("Jakarta Authorization: constraint translation: begin parsing web resource collection");
    
                // Enumerate over URLPatterns within collection
                for (String urlPattern :  webResourceCollection.getUrlPatterns()) {
                    
                    // FIX TO BE CONFIRMED (will we ever?)
                    urlPattern = urlPattern.replaceAll(":", "%3A");
    
                    if (logger.isLoggable(FINE)) {
                        logger.fine("Jakarta Authorization: constraint translation: process url pattern: " + urlPattern);
                    }
    
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
    
                    if (logger.isLoggable(FINE)) {
                        logger.fine("Jakarta Authorization: constraint translation: end processing url pattern: " + urlPattern);
                    }
                }
    
                logger.fine("Jakarta Authorization: constraint translation: end parsing web resource collection");
            }

            logger.fine("Jakarta Authorization: constraint translation: end parsing security constraint");
        }

        if (logger.isLoggable(FINE)) {
            logger.exiting(CLASS_NAME, "parseConstraints");
        }

        return patternBuilderMap.values();
    }
    
    private static JakartaPermissions intermediatePatternsToPermissions(Collection<PatternBuilder> patterns, boolean isDenyUncoveredHttpMethods) {
        logger.log(FINE, () ->
            "Jakarta Authorization: constraint capture: begin processing qualified url patterns" +
            " - uncovered http methods will be " +
            (isDenyUncoveredHttpMethods ? "denied" : "permitted"));
        
        
        JakartaPermissions jakartaPermissions = new JakartaPermissions();
        
        for (PatternBuilder patternBuilder : patterns) {
            if (!patternBuilder.isIrrelevantByQualifier()) {

                String urlPatternSpec = patternBuilder.getUrlPatternSpec();

                if (logger.isLoggable(FINE)) {
                    logger.fine("Jakarta Authorization: constraint capture: urlPattern: " + urlPatternSpec);
                }

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

        if (logger.isLoggable(FINE)) {
            logger.fine("Jakarta Authorization: constraint capture: adding excluded methods: " + actions);
        }
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

        if (logger.isLoggable(FINE)) {
            logger.fine("Jakarta Authorization: constraint capture: adding unchecked (for authorization) methods: " + httpMethodSpec);
        }
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

            if (logger.isLoggable(FINE)) {
                logger.fine(
                    "Jakarta Authorization: constraint capture: adding methods that accept connections with protection: " +
                    transport + " methods: " + actions);
            }
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

        if (logger.isLoggable(FINE)) {
            logger.fine("Jakarta Authorization: constraint capture: adding methods to role: " + roleName + " methods: " + permission.getActions());
        }
    }

    private static void logExcludedUncheckedPermissionsWritten(Permissions excluded, Permissions unchecked) {
        if (logger.isLoggable(FINE)) {
            logger.fine("Jakarta Authorization: constraint capture: end processing qualified url patterns");

            for (Permission permission :  list(excluded.elements())) {
                logger.fine("Jakarta Authorization: permission(excluded) type: " + permissionType(permission) + " name: " + permission.getName() + " actions: " + permission.getActions());
            }

            for (Permission permission :  list(unchecked.elements())) {
                logger.fine("Jakarta Authorization: permission(unchecked) type: " + permissionType(permission) + " name: " + permission.getName() + " actions: " + permission.getActions());
            }
        }
    }

    private static void logPerRolePermissionsWritten(String role, Permissions permissions) {
        if (logger.isLoggable(FINE)) {
            for (Permission permission :  list(permissions.elements())) {
                logger.fine("Jakarta Authorization: permission(" + role + ") type: " + permissionType(permission) + " name: " + permission.getName() + " actions: " + permission.getActions());
            }

        }
    }
    
    private static String permissionType(Permission permission) {
        return permission instanceof WebResourcePermission ? "WRP  " : "WUDP ";
    }
}
