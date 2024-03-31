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

import jakarta.servlet.annotation.ServletSecurity.TransportGuarantee;

import java.lang.System.Logger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.lang.System.Logger.Level.DEBUG;

/**
 * @author Harpreet Singh
 * @author Jean-Francois Arcand
 * @author Ron Monzillo
 * @author Arjan Tijms (refactoring)
 */
public class ConstraintValue {

    private static final Logger LOG = System.getLogger(ConstraintValue.class.getName());

    public static final String connectKeys[] = { "NONE", "INTEGRAL", "CONFIDENTIAL" };

    public static final int connectTypeNone = 1;
    static Map<String, Integer> connectHash = new HashMap<>();
    static {
        for (int i = 0; i < connectKeys.length; i++) {
            connectHash.put(connectKeys[i], Integer.valueOf(1 << i));
        }
    }

    private boolean excluded;
    private boolean ignoreRoles;
    private final List<String> roles = new ArrayList<>();

    private int connectSet;


    void setRole(String role) {
        synchronized (roles) {
            if (!roles.contains(role)) {
                roles.add(role);
            }
        }
    }

    void removeRole(String role) {
        synchronized (roles) {
            if (roles.contains(role)) {
                roles.remove(role);
            }
        }
    }

    public List<String> getRoles() {
        return roles;
    }

    boolean isExcluded() {
        return excluded;
    }

    boolean isUncovered() {
        if (excluded) {
            return false;
        }

        return !ignoreRoles && roles.isEmpty() && connectSet == 0;
    }

    boolean isAuthConstrained() {
        if (excluded) {
            return true;
        }

        if (ignoreRoles || roles.isEmpty()) {
            return false;
        }

        return true;
    }

    void addConnectType(TransportGuarantee guarantee) {
        int b = connectTypeNone;

        if (guarantee != null) {
            Integer bit = connectHash.get(guarantee.name());
            if (bit == null) {
                throw new IllegalArgumentException("constraint translation error-illegal trx guarantee");
            }

            b = bit.intValue();
        }

        connectSet |= b;
    }

    boolean isConnectAllowed(int connectType) {
        if (excluded) {
            return false;
        }

        return connectSet == 0 || containsConnectType(connectTypeNone) || containsConnectType(connectType);
    }

    private boolean containsConnectType(int connectType) {
        return bitIsSet(connectSet, connectType);
    }

    private static boolean bitIsSet(int map, int bit) {
        return (map & bit) == bit;
    }

    /*
     * IgnoreRoleList is true if there was a security-constraint without an auth-constraint; such a constraint combines to
     * allow access without authentication.
     */


    void setOutcome(Set<String> declaredRoles, Set<String> constraintRolesAllowed, TransportGuarantee transportGuarantee) {

        // ### 1 Handle roles

        if (constraintRolesAllowed == null) {

            // No roles means unchecked: access is always granted

            setPredefinedOutcome(true);
        } else if (constraintRolesAllowed.isEmpty()) {

            // Empty roles means excluded: access is always denied

            setPredefinedOutcome(false);
        } else {

            // Non-empty roles means access is per role


            // Tracks if the special "all Roles" role ("*") is present.
            boolean containsAllRoles = false;

            for (String roleName : constraintRolesAllowed) {
                if ("*".equals(roleName)) {
                    containsAllRoles = true;
                } else {
                    setRole(roleName);
                }
            }

            /**
             * JACC MR8 When role '*' named, do not include any authenticated user role '**' unless an application defined a role
             * named '**'
             */
            if (containsAllRoles) {
                removeRole("**");
                // The "all role" role ("*") indicates that all declared roles in the application
                // should be added.
                for (String role : declaredRoles) {
                    setRole(role);
                }
            }
        }


        // ### 2 Handle transport guarantee

        addConnectType(transportGuarantee);

        LOG.log(DEBUG, "setOutcome yields: {0}", this);
    }

    void setPredefinedOutcome(boolean outcome) {
        if (!outcome) {
            excluded = true;
        } else {
            ignoreRoles = true;
        }
    }

    void setValue(ConstraintValue constraint) {
        excluded = constraint.excluded;
        ignoreRoles = constraint.ignoreRoles;

        roles.clear();
        roles.addAll(constraint.roles);

        connectSet = constraint.connectSet;
    }

    @Override
    public String toString() {
        StringBuilder rolesBuilder = new StringBuilder(" roles: ");
        for (String role : roles) {
            rolesBuilder.append(" ").append(role);
        }

        StringBuilder transportsBuilder = new StringBuilder("transports: ");
        for (int i = 0; i < connectKeys.length; i++) {
            if (isConnectAllowed(1 << i)) {
                transportsBuilder.append(" ").append(connectKeys[i]);
            }
        }

        return " ConstraintValue ( " + " excluded: " + excluded + " ignoreRoleList: " + ignoreRoles + rolesBuilder + transportsBuilder + " ) ";
    }

    /*
     * IgnoreRoleList is true if there was a security-constraint without an auth-constraint; such a constraint combines to
     * allow access without authentication.
     */

}