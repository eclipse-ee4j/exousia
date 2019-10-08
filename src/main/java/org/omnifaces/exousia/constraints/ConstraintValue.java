package org.omnifaces.exousia.constraints;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import javax.management.relation.Role;

public class ConstraintValue {

    static String connectKeys[] = { "NONE", "INTEGRAL", "CONFIDENTIAL" };

    static int connectTypeNone = 1;
    static HashMap<String, Integer> connectHash = new HashMap<String, Integer>();
    static {
        for (int i = 0; i < connectKeys.length; i++)
            connectHash.put(connectKeys[i], Integer.valueOf(1 << i));
    };

    boolean excluded;
    boolean ignoreRoleList;
    final List<String> roleList = new ArrayList<String>();
    int connectSet;

    ConstraintValue() {
        excluded = false;
        ignoreRoleList = false;
        // roleList = new ArrayList<String>();
        connectSet = 0;
    }

    static boolean bitIsSet(int map, int bit) {
        return (map & bit) == bit ? true : false;
    }

    void setRole(String role) {
        synchronized (roleList) {
            if (!roleList.contains(role)) {
                roleList.add(role);
            }
        }
    }

    void removeRole(String role) {
        synchronized (roleList) {
            if (roleList.contains(role)) {
                roleList.remove(role);
            }
        }
    }

    void setPredefinedOutcome(boolean outcome) {
        if (!outcome) {
            excluded = true;
        } else {
            ignoreRoleList = true;
        }
    }

    void addConnectType(String guarantee) {
        int b = connectTypeNone;
        if (guarantee != null) {
            Integer bit = connectHash.get(guarantee);
            if (bit == null)
                throw new IllegalArgumentException("constraint translation error-illegal trx guarantee");
            b = bit.intValue();
        }

        connectSet |= b;
    }

    boolean isExcluded() {
        return excluded;
    }

    /*
     * ignoreRoleList is true if there was a security-constraint without an auth-constraint; such a constraint combines to
     * allow access without authentication.
     */
    boolean isAuthConstrained() {
        if (excluded) {
            return true;
        } else if (ignoreRoleList || roleList.isEmpty()) {
            return false;
        }
        return true;
    }

    boolean isTransportConstrained() {
        if (excluded || (connectSet != 0 && !bitIsSet(connectSet, connectTypeNone))) {
            return true;
        }
        return false;
    }

    boolean isConnectAllowed(int cType) {
        if (!excluded && (connectSet == 0 || bitIsSet(connectSet, connectTypeNone) || bitIsSet(connectSet, cType))) {
            return true;
        }
        return false;
    }

    void setOutcome(Set<Role> roleSet, AuthorizationConstraint ac, UserDataConstraint udc) {
        if (ac == null) {
            setPredefinedOutcome(true);
        } else {
            boolean containsAllRoles = false;
            Enumeration eroles = ac.getSecurityRoles();
            if (!eroles.hasMoreElements()) {
                setPredefinedOutcome(false);
            } else
                while (eroles.hasMoreElements()) {
                    SecurityRoleDescriptor srd = (SecurityRoleDescriptor) eroles.nextElement();
                    String roleName = srd.getName();
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
                Iterator it = roleSet.iterator();
                while (it.hasNext()) {
                    setRole(((Role) it.next()).getName());
                }
            }
        }
        addConnectType(udc == null ? null : udc.getTransportGuarantee());

        if (ConstraintsToPermissionsTransformer.logger.isLoggable(Level.FINE)) {
            ConstraintsToPermissionsTransformer.logger.log(Level.FINE, "JACC: setOutcome yields: " + toString());
        }

    }

    void setValue(ConstraintValue constraint) {
        excluded = constraint.excluded;
        ignoreRoleList = constraint.ignoreRoleList;
        roleList.clear();
        Iterator rit = constraint.roleList.iterator();
        while (rit.hasNext()) {
            String role = (String) rit.next();
            roleList.add(role);
        }
        connectSet = constraint.connectSet;
    }

    public String toString() {
        StringBuilder roles = new StringBuilder(" roles: ");
        Iterator rit = roleList.iterator();
        while (rit.hasNext()) {
            roles.append(" ").append((String) rit.next());
        }
        StringBuilder transports = new StringBuilder("transports: ");
        for (int i = 0; i < connectKeys.length; i++) {
            if (isConnectAllowed(1 << i)) {
                transports.append(" ").append(connectKeys[i]);
            }
        }
        return " ConstraintValue ( " + " excluded: " + excluded + " ignoreRoleList: " + ignoreRoleList + roles + transports + " ) ";
    }

    /*
     * ignoreRoleList is true if there was a security-constraint without an auth-constraint; such a constraint combines to
     * allow access without authentication.
     */
    boolean isUncovered() {
        return (!excluded && !ignoreRoleList && roleList.isEmpty() && connectSet == 0);
    }
}