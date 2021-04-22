/*
 * Copyright (c) 2019 OmniFaces. All rights reserved.
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
package org.glassfish.exousia.modules.def;

import static java.util.Collections.list;

import java.security.Permission;
import java.security.PermissionCollection;

import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyContextException;

/**
 * 
 * @author Arjan Tijms
 */
public abstract class DefaultPolicyConfigurationBase implements PolicyConfiguration {
     
    private final String contextID;
     
    public DefaultPolicyConfigurationBase(String contextID) {
        this.contextID = contextID;
    }
     
    @Override
    public String getContextID() throws PolicyContextException {
        return contextID;
    }
     
    @Override
    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException {
        for (Permission permission : list(permissions.elements())) {
            addToExcludedPolicy(permission);
        }
    }
     
    @Override
    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException {
        for (Permission permission : list(permissions.elements())) {
            addToUncheckedPolicy(permission);
        }
    }
     
    @Override
    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException {
        for (Permission permission : list(permissions.elements())) {
            addToRole(roleName, permission);
        }
    }
 
    @Override
    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException {
    }
     
    @Override
    public boolean inService() throws PolicyContextException {
        // Not used, taken care of by PolicyConfigurationStateMachine
        return true;
    }
 
}