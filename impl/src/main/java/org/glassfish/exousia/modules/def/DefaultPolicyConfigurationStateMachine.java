/*
 * Copyright (c) 2023 Contributors to the Eclipse Foundation.
 * Copyright (c) 2019, 2021 OmniFaces. All rights reserved.
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

import static org.glassfish.exousia.modules.def.DefaultPolicyConfigurationStateMachine.State.DELETED;
import static org.glassfish.exousia.modules.def.DefaultPolicyConfigurationStateMachine.State.INSERVICE;
import static org.glassfish.exousia.modules.def.DefaultPolicyConfigurationStateMachine.State.OPEN;

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;

import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyContextException;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultPolicyConfigurationStateMachine implements PolicyConfiguration {

    public static enum State {
        OPEN, INSERVICE, DELETED
    };

    private State state = OPEN;
    private PolicyConfiguration policyConfiguration;

    public DefaultPolicyConfigurationStateMachine(PolicyConfiguration policyConfiguration) {
        this.policyConfiguration = policyConfiguration;
    }

    public PolicyConfiguration getPolicyConfiguration() {
        return policyConfiguration;
    }

    // ### Methods that can be called in any state
    // and don't change state

    @Override
    public String getContextID() throws PolicyContextException {
        return policyConfiguration.getContextID();
    }

    @Override
    public boolean inService() throws PolicyContextException {
        return state == INSERVICE;
    }

    // ### Methods where state should be OPEN
    // and don't change state

    @Override
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToExcludedPolicy(permission);
    }

    @Override
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToUncheckedPolicy(permission);
    }

    @Override
    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToRole(roleName, permission);
    }

    @Override
    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToExcludedPolicy(permissions);
    }

    @Override
    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToUncheckedPolicy(permissions);
    }

    @Override
    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToRole(roleName, permissions);
    }

    @Override
    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.linkConfiguration(link);
    }

    @Override
    public void removeExcludedPolicy() throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.removeExcludedPolicy();

    }

    @Override
    public void removeRole(String roleName) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.removeRole(roleName);
    }

    @Override
    public void removeUncheckedPolicy() throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.removeUncheckedPolicy();
    }

    // Methods that change the state
    //
    // commit() can only be called when
    // the state is OPEN or INSERVICE
    // and next state is always INSERVICE
    //
    // delete() can always be called and
    // target state will always be DELETED
    //
    // open() can always be called and
    // target state will always be OPEN

    @Override
    public void commit() throws PolicyContextException {
        checkStateIsNot(DELETED);

        if (state == OPEN) {
            policyConfiguration.commit();
            state = INSERVICE;
        }
    }

    @Override
    public void delete() throws PolicyContextException {
        policyConfiguration.delete();
        state = DELETED;
    }

    @Override
    public Map<String, PermissionCollection> getPerRolePermissions() {
        return policyConfiguration.getPerRolePermissions();
    }

    @Override
    public PermissionCollection getUncheckedPermissions() {
        return policyConfiguration.getUncheckedPermissions();
    }

    @Override
    public PermissionCollection getExcludedPermissions() {
        return policyConfiguration.getExcludedPermissions();
    }

    /**
     * Transition back to open.
     */
    public void open() {
        state = OPEN;
    }

    // ### Private methods

    private void checkStateIs(State requiredState) {
        if (state != requiredState) {
            throw new IllegalStateException("Required status is " + requiredState + " but actual state is " + state);
        }
    }

    private void checkStateIsNot(State undesiredState) {
        if (state == undesiredState) {
            throw new IllegalStateException("State could not be " + undesiredState + " but actual state is");
        }
    }

}