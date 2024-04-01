/*
 * Copyright (c) 2023, 2024 Contributors to Eclipse Foundation.
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

package org.glassfish.exousia.modules.locked;

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;

import java.lang.System.Logger;
import java.security.Permission;
import java.security.PermissionCollection;

import javax.security.auth.Subject;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.TRACE;


/**
 *
 * @author monzillo
 */
public class SimplePolicyProvider implements Policy {

    private static final Logger LOG = System.getLogger(SimplePolicyProvider.class.getName());
    private static final String REUSE = "java.security.Policy.supportsReuse";

    /**
     * ThreadLocal object to keep track of the reentrancy status of each thread. It contains a byte[] object whose single
     * element is either 0 (initial value or no reentrancy), or 1 (current thread is reentrant). When a thread exists the
     * implies method, byte[0] is always reset to 0.
     */
    private static ThreadLocal<Object> reentrancyStatus = new ThreadLocal<>() {
        @Override
        protected synchronized Object initialValue() {
            return new byte[] { 0 };
        }
    };

    /**
     * Evaluates the global policy for the permissions granted to the ProtectionDomain and tests whether the permission is
     * granted.
     *
     * @param permissionToBeChecked the Permission object to be tested for implication.
     * @param subject the Subject to test
     *
     * @return true if "permission" is a proper subset of a permission granted to this ProtectionDomain.
     *
     * @see java.security.ProtectionDomain
     * @since 1.4
     */
    @Override
    public boolean implies(Permission permissionToBeChecked, Subject subject) {
        byte[] alreadyCalled = (byte[]) reentrancyStatus.get();
        if (alreadyCalled[0] == 1) {
            return true;
        }

        alreadyCalled[0] = 1;
        try {
            return doImplies(permissionToBeChecked, subject);
        } finally {
            alreadyCalled[0] = 0;
        }
    }

    private boolean doImplies(Permission permissionToBeChecked, Subject subject) {
        int implies = 1;
        try {
            implies = SimplePolicyConfiguration.implies(permissionToBeChecked, subject);
            if (implies > 0) {
                LOG.log(TRACE, "SimplePolicyConfiguration returned implies = {0}, returning true.", implies);
                return true;
            }
        } catch (PolicyContextException e) {
            LOG.log(TRACE, "SimplePolicyConfiguration.implies failed.", e);
        }

        LOG.log(DEBUG, "Access refused for the policy context id {0}, permission {1} and subject {2}.",
            PolicyContext.getContextID(), permissionToBeChecked, subject);

        return false;
    }

    /**
     * Refreshes/reloads the policy configuration. The behavior of this method depends on the implementation. For example,
     * calling <code>refresh</code> on a file-based policy will cause the file to be re-read.
     *
     */
    @Override
    public void refresh() {
        try {
            // will enable permission caching of container, unless REUSE
            // property is set, and its value is not "true".
            String propValue = System.getProperty(REUSE);
            boolean supportsReuse = (propValue == null ? true : Boolean.parseBoolean(propValue));
            if (supportsReuse) {
                if (PolicyContext.getHandlerKeys().contains(REUSE)) {
                    PolicyContext.getContext(REUSE);
                }
            }
            SimplePolicyConfiguration.refresh();
        } catch (PolicyContextException pce) {
            throw new IllegalStateException("Refresh failed", pce);
        }
    }

    @Override
    public PermissionCollection getPermissionCollection(Subject subject) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean impliesByRole(Permission permissionToBeChecked, Subject subject) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isExcluded(Permission permissionToBeChecked) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isUnchecked(Permission permissionToBeChecked) {
        // TODO Auto-generated method stub
        return false;
    }

    /*
     * NB:
     * Excluded permissions should be removed from the collections returned by getPermissions.
     * Permissions that imply excluded permissions should also be excluded.
     *
     * There is a potential semantic integrity issue if the excluded permissions have been
     * assigned to the protection domain. The calls to getPermissions and implies of SimplePolicyConfiguration remove
     * excluded permissions from the returned results.
     */
}
