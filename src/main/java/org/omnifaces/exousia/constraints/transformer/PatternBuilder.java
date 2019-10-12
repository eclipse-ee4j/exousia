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

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;

import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.annotation.ServletSecurity.TransportGuarantee;

/**
 * @author Harpreet Singh
 * @author Jean-Francois Arcand
 * @author Ron Monzillo
 * @author Arjan Tijms (refactoring)
 */
public class PatternBuilder {
    
    private static final Logger logger = Logger.getLogger(PatternBuilder.class.getName());

    private final int patternLength;

    private final Map<String, MethodValue> methodValues = new HashMap<>();

    boolean committed;
    
    private final ConstraintValue otherConstraint;
    
    private boolean irrelevantByQualifier;
    
    private final StringBuilder urlPatternSpec;

    PatternBuilder(String urlPattern) {
        patternLength = urlPattern.length();
        urlPatternSpec = new StringBuilder(urlPattern);
        otherConstraint = new ConstraintValue();
    }

    void addQualifier(String urlPattern) {
        if (ConstraintsToPermissionsTransformer.implies(urlPattern, urlPatternSpec.substring(0, patternLength))) {
            irrelevantByQualifier = true;
        }

        urlPatternSpec.append(":" + urlPattern);
    }
    
    ConstraintValue getOtherConstraint() {
        return otherConstraint;
    }
    
    boolean isIrrelevantByQualifier() {
        return irrelevantByQualifier;
    }
    
    String getUrlPatternSpec() {
        return urlPatternSpec.toString();
    }

    MethodValue getMethodValue(int methodIndex) {
        String methodName = MethodValue.getMethodName(methodIndex);

        synchronized (methodValues) {
            MethodValue methodValue = methodValues.get(methodName);
            if (methodValue == null) {
                methodValue = new MethodValue(methodName, otherConstraint);
                methodValues.put(methodName, methodValue);

                if (logger.isLoggable(FINE)) {
                    logger.log(FINE, "JACC: created MethodValue: " + methodValue);
                }
            }

            return methodValue;
        }
    }

    BitSet getExcludedMethods() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {
            for (MethodValue methodValue : methodValues.values()) {
                if (methodValue.isExcluded()) {
                    methodSet.set(methodValue.index);
                }
            }
        }

        return methodSet;
    }

    BitSet getNoAuthMethods() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {
            for (MethodValue methodValue : methodValues.values()) {
                if (!methodValue.isAuthConstrained()) {
                    methodSet.set(methodValue.index);
                }
            }
        }

        return methodSet;
    }

    /**
     * Map of methods allowed per role
     */
    HashMap<String, BitSet> getRoleMap() {
        HashMap<String, BitSet> roleMap = new HashMap<>();

        synchronized (methodValues) {
            for (MethodValue methodValue : methodValues.values()) {
                if (!methodValue.isExcluded() && methodValue.isAuthConstrained()) {
                    for (String role : methodValue.getRoles()) {
                        roleMap.computeIfAbsent(role, e -> new BitSet())
                               .set(methodValue.index);
                    }
                }
            }
        }

        return roleMap;
    }

    BitSet getConnectMap(int cType) {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {
            for (MethodValue methodValue : methodValues.values()) {
                /*
                 * NOTE WELL: prior version of this method could not be called during constraint parsing because it finalized the
                 * connectSet when its value was 0 (indicating any connection, until some specific bit is set) if (v.connectSet == 0) {
                 * v.connectSet = MethodValue.connectTypeNone; }
                 */

                if (methodValue.isConnectAllowed(cType)) {
                    methodSet.set(methodValue.index);
                }
            }
        }

        return methodSet;
    }

    BitSet getMethodSet() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {
            for (MethodValue methodValue : methodValues.values()) {
                methodSet.set(methodValue.index);
            }
        }

        return methodSet;
    }

    void setMethodOutcomes(Set<String> roleSet, Set<String> constraintRolesAllowed, TransportGuarantee transportGuarantee, BitSet methods, BitSet omittedMethods) {

        committed = true;

        if (omittedMethods != null) {

            // Get the omitted methodSet
            BitSet methodsInMap = getMethodSet();

            BitSet saved = (BitSet) omittedMethods.clone();

            // Determine methods being newly omitted
            omittedMethods.andNot(methodsInMap);

            // Create values for newly omitted, init from otherConstraint
            for (int i = omittedMethods.nextSetBit(0); i >= 0; i = omittedMethods.nextSetBit(i + 1)) {
                getMethodValue(i);
            }

            // Combine this constraint into constraint on all other methods
            otherConstraint.setOutcome(roleSet, constraintRolesAllowed, transportGuarantee);

            methodsInMap.andNot(saved);

            // Recursive call to combine constraint into prior omitted methods
            setMethodOutcomes(roleSet, constraintRolesAllowed, transportGuarantee, methodsInMap, null);

        } else {
            for (int i = methods.nextSetBit(0); i >= 0; i = methods.nextSetBit(i + 1)) {
                // Create values (and init from otherConstraint) if not in map
                // then combine with this constraint.
                getMethodValue(i).setOutcome(roleSet, constraintRolesAllowed, transportGuarantee);
            }
        }
    }

    void handleUncovered(boolean deny) {

        // Bypass any uncommitted patterns (e.g. the default pattern) which were entered in the map, but that were not named in
        // a security constraint

        if (!committed) {
            return;
        }

        boolean otherIsUncovered = false;
        synchronized (methodValues) {
            BitSet uncoveredMethodSet = new BitSet();

            // For all the methods in the mapValue
            for (MethodValue methodValue : methodValues.values()) {
                // If the method is uncovered add its id to the uncovered set
                if (methodValue.isUncovered()) {
                    if (deny) {
                        methodValue.setPredefinedOutcome(false);
                    }
                    uncoveredMethodSet.set(methodValue.index);
                }
            }

            // If the constraint on all other methods is uncovered
            if (otherConstraint.isUncovered()) {

                // This is the case where the problem is most severe, since a non-enumerable set of HTTP methods has
                // been left uncovered.
                // The set of method will be logged and denied.

                otherIsUncovered = true;
                if (deny) {
                    otherConstraint.setPredefinedOutcome(false);
                }

                // Ensure that the methods that are reported as uncovered includes any enumerated methods that were found to be
                // uncovered.
                BitSet otherMethodSet = getMethodSet();
                if (!uncoveredMethodSet.isEmpty()) {

                    // UncoveredMethodSet contains methods that otherConstraint pertains to, so remove them from otherMethodSet
                    // which is the set to which the otherConstraint does not apply
                    otherMethodSet.andNot(uncoveredMethodSet);
                }


                // When otherIsUncovered, uncoveredMethodSet contains methods to which otherConstraint does NOT apply
                uncoveredMethodSet = otherMethodSet;
            }

            if (otherIsUncovered || !uncoveredMethodSet.isEmpty()) {
                String uncoveredMethods = MethodValue.getActions(uncoveredMethodSet);
                Object[] args = new Object[] { urlPatternSpec, uncoveredMethods };

                if (deny) {
                    if (otherIsUncovered) {
                        logger.log(INFO, "Jakarta Authorization: For the URL pattern {0}, all but the following methods have been excluded: {1}", args);
                    } else {
                        logger.log(INFO, "Jakarta Authorization: For the URL pattern {0}, the following methods have been excluded: {1}", args);
                    }
                } else {
                    if (otherIsUncovered) {
                        logger.log(WARNING, "Jakarta Authorization: For the URL pattern {0}, all but the following methods were uncovered: {1}", args);
                    } else {
                        logger.log(WARNING, "Jakarta Authorization: For the URL pattern {0}, the following methods were uncovered: {1}", args);
                    }
                }
            }
        }
    }
}