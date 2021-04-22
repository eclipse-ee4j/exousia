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

import java.security.Permission;
import java.security.Permissions;
import java.util.HashMap;
import java.util.Map;

import jakarta.security.jacc.PolicyContextException;
 
/**
 * 
 * @author Arjan Tijms
 */
public abstract class DefaultPolicyConfigurationPermissions extends DefaultPolicyConfigurationBase {
 
    private Permissions excludedPermissions = new Permissions();
    private Permissions uncheckedPermissions = new Permissions();
    private Map<String, Permissions> perRolePermissions = new HashMap<String, Permissions>();
     
    public DefaultPolicyConfigurationPermissions(String contextID) {
        super(contextID);
    }
 
    @Override
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
        excludedPermissions.add(permission);
    }
 
    @Override
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        uncheckedPermissions.add(permission);
    }
 
    @Override
    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        Permissions permissions = perRolePermissions.get(roleName);
        if (permissions == null) {
            permissions = new Permissions();
            perRolePermissions.put(roleName, permissions);
        }
         
        permissions.add(permission);
    }
     
    @Override
    public void delete() throws PolicyContextException {
        removeExcludedPolicy();
        removeUncheckedPolicy();
        perRolePermissions.clear();
    }
 
    @Override
    public void removeExcludedPolicy() throws PolicyContextException {
        excludedPermissions = new Permissions();
    }
 
    @Override
    public void removeRole(String roleName) throws PolicyContextException {
        if (perRolePermissions.containsKey(roleName)) {
            perRolePermissions.remove(roleName);
        } else if ("*".equals(roleName)) {
            perRolePermissions.clear();
        }
    }
 
    @Override
    public void removeUncheckedPolicy() throws PolicyContextException {
        uncheckedPermissions = new Permissions();
    }
     
    public Permissions getExcludedPermissions() {
        return excludedPermissions;
    }
 
    public Permissions getUncheckedPermissions() {
        return uncheckedPermissions;
    }
 
    public Map<String, Permissions> getPerRolePermissions() {
        return perRolePermissions;
    }
 
}