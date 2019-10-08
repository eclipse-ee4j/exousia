package org.omnifaces.exousia.constraints;

import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.management.relation.Role;

public class MapValue {

    boolean committed;

    int patternType;

    int patternLength;

    boolean irrelevantByQualifier;

    StringBuffer urlPatternSpec;

    final HashMap<String, MethodValue> methodValues = new HashMap<String, MethodValue>();

    ConstraintValue otherConstraint;

    MapValue(String urlPattern) {
        this.committed = false;
        this.patternType = WebPermissionUtil.patternType(urlPattern);
        this.patternLength = urlPattern.length();
        this.irrelevantByQualifier = false;
        this.urlPatternSpec = new StringBuffer(urlPattern);
        otherConstraint = new ConstraintValue();
    }

    void addQualifier(String urlPattern) {
        if (WebPermissionUtil.implies(urlPattern, this.urlPatternSpec.substring(0, this.patternLength)))
            this.irrelevantByQualifier = true;
        this.urlPatternSpec.append(":" + urlPattern);
    }

    MethodValue getMethodValue(int methodIndex) {
        String methodName = MethodValue.getMethodName(methodIndex);
        synchronized (methodValues) {
            MethodValue methodValue = methodValues.get(methodName);
            if (methodValue == null) {
                methodValue = new MethodValue(methodName, otherConstraint);
                methodValues.put(methodName, methodValue);

                if (WebPermissionUtil.logger.isLoggable(Level.FINE)) {
                    WebPermissionUtil.logger.log(Level.FINE, "JACC: created MethodValue: " + methodValue);
                }
            }
            return methodValue;
        }
    }

    BitSet getExcludedMethods() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {

            Collection<MethodValue> values = methodValues.values();

            for (MethodValue v : values) {
                if (v.isExcluded()) {
                    methodSet.set(v.index);
                }
            }
        }
        return methodSet;
    }

    BitSet getNoAuthMethods() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {

            Collection<MethodValue> values = methodValues.values();
            for (MethodValue v : values) {
                if (!v.isAuthConstrained()) {
                    methodSet.set(v.index);
                }
            }
        }
        return methodSet;
    }

    BitSet getAuthConstrainedMethods() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {

            Collection<MethodValue> values = methodValues.values();

            for (MethodValue v : values) {
                if (v.isAuthConstrained()) {
                    methodSet.set(v.index);
                }
            }
        }
        return methodSet;
    }

    BitSet getTransportConstrainedMethods() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {

            Collection<MethodValue> values = methodValues.values();

            for (MethodValue v : values) {
                if (v.isTransportConstrained()) {
                    methodSet.set(v.index);
                }
            }
        }
        return methodSet;
    }

    /**
     * Map of methods allowed per role
     */
    HashMap<String, BitSet> getRoleMap() {
        HashMap<String, BitSet> roleMap = new HashMap<String, BitSet>();

        synchronized (methodValues) {

            Collection<MethodValue> values = methodValues.values();

            for (MethodValue v : values) {
                if (!v.isExcluded() && v.isAuthConstrained()) {
                    for (String role : v.roleList) {
                        BitSet methodSet = roleMap.get(role);

                        if (methodSet == null) {
                            methodSet = new BitSet();
                            roleMap.put(role, methodSet);
                        }

                        methodSet.set(v.index);
                    }
                }
            }
        }

        return roleMap;
    }

    BitSet getConnectMap(int cType) {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {

            Collection<MethodValue> values = methodValues.values();
            for (MethodValue v : values) {
                /*
                 * NOTE WELL: prior version of this method could not be called during constraint parsing because it finalized the
                 * connectSet when its value was 0 (indicating any connection, until some specific bit is set)
                 *
                 * if (v.connectSet == 0) { v.connectSet = MethodValue.connectTypeNone; }
                 * 
                 */

                if (v.isConnectAllowed(cType)) {
                    methodSet.set(v.index);
                }
            }
        }

        return methodSet;
    }

    BitSet getMethodSet() {
        BitSet methodSet = new BitSet();

        synchronized (methodValues) {

            Collection<MethodValue> values = methodValues.values();
            for (MethodValue v : values) {
                methodSet.set(v.index);
            }
        }

        return methodSet;
    }

    void setMethodOutcomes(Set<Role> roleSet, AuthorizationConstraint ac, UserDataConstraint udc, BitSet methods, BitSet omittedMethods) {

        committed = true;

        if (omittedMethods != null) {

            // get the ommitted methodSet
            BitSet methodsInMap = getMethodSet();

            BitSet saved = (BitSet) omittedMethods.clone();

            // determine methods being newly omitted
            omittedMethods.andNot(methodsInMap);

            // create values for newly omitted, init from otherConstraint
            for (int i = omittedMethods.nextSetBit(0); i >= 0; i = omittedMethods.nextSetBit(i + 1)) {
                getMethodValue(i);
            }

            // combine this constraint into constraint on all other methods
            otherConstraint.setOutcome(roleSet, ac, udc);

            methodsInMap.andNot(saved);

            // recursive call to combine constraint into prior omitted methods
            setMethodOutcomes(roleSet, ac, udc, methodsInMap, null);

        } else {

            for (int i = methods.nextSetBit(0); i >= 0; i = methods.nextSetBit(i + 1)) {
                // create values (and init from otherConstraint) if not in map
                // then combine with this constraint.
                getMethodValue(i).setOutcome(roleSet, ac, udc);
            }
        }
    }

    void handleUncoveredMethods(boolean deny) {
        /*
         * bypass any uncommitted patterns (e.g. the default pattern) which were entered in the map, but that were not named in
         * a security constraint
         */
        if (!committed) {
            return;
        }

        boolean otherIsUncovered = false;
        synchronized (methodValues) {
            BitSet uncoveredMethodSet = new BitSet();
            // for all the methods in the mapValue
            for (MethodValue v : methodValues.values()) {
                // if the method is uncovered add its id to the uncovered set
                if (v.isUncovered()) {
                    if (deny) {
                        v.setPredefinedOutcome(false);
                    }
                    uncoveredMethodSet.set(v.index);
                }
            }
            // if the constraint on all other methods is uncovered
            if (otherConstraint.isUncovered()) {
                /*
                 * this is the case where the problem is most severe, since a non-enumerble set of http methods has been left uncovered.
                 * the set of method will be logged and denied.
                 */
                otherIsUncovered = true;
                if (deny) {
                    otherConstraint.setPredefinedOutcome(false);
                }
                /*
                 * ensure that the methods that are reported as uncovered includes any enumerated methods that were found to be
                 * uncovered.
                 */
                BitSet otherMethodSet = getMethodSet();
                if (!uncoveredMethodSet.isEmpty()) {
                    /*
                     * uncoveredMethodSet contains methods that otherConstraint pertains to, so remove them from otherMethodSet which is the
                     * set to which the otherConstraint does not apply
                     */
                    otherMethodSet.andNot(uncoveredMethodSet);
                }
                /*
                 * when otherIsUncovered, uncoveredMethodSet contains methods to which otherConstraint does NOT apply
                 */
                uncoveredMethodSet = otherMethodSet;
            }
            if (otherIsUncovered || !uncoveredMethodSet.isEmpty()) {
                String uncoveredMethods = MethodValue.getActions(uncoveredMethodSet);
                Object[] args = new Object[] { urlPatternSpec, uncoveredMethods };
                if (deny) {
                    if (otherIsUncovered) {
                        WebPermissionUtil.logger.log(Level.INFO, LogUtils.NOT_EXCLUDED_METHODS, args);
                    } else {
                        WebPermissionUtil.logger.log(Level.INFO, LogUtils.EXCLUDED_METHODS, args);
                    }
                } else {
                    if (otherIsUncovered) {
                        WebPermissionUtil.logger.log(Level.WARNING, LogUtils.NOT_UNCOVERED_METHODS, args);
                    } else {
                        WebPermissionUtil.logger.log(Level.WARNING, LogUtils.UNCOVERED_METHODS, args);
                    }
                }
            }
        }
    }
}