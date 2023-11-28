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

import static jakarta.security.jacc.PolicyContext.getContextID;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContextException;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultPolicyConfigurationFactory extends PolicyConfigurationFactory {

    private static final ConcurrentMap<String, DefaultPolicyConfigurationStateMachine> configurators = new ConcurrentHashMap<>();

    @Override
    public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {

        DefaultPolicyConfigurationStateMachine defaultPolicyConfigurationStateMachine =
            configurators.computeIfAbsent(contextID,
                contextId -> new DefaultPolicyConfigurationStateMachine(new DefaultPolicyConfiguration(contextID)));

        if (remove) {
            defaultPolicyConfigurationStateMachine.delete();
        }

        defaultPolicyConfigurationStateMachine.open();

        return defaultPolicyConfigurationStateMachine;
    }

    @Override
    public boolean inService(String contextID) throws PolicyContextException {
        DefaultPolicyConfigurationStateMachine defaultPolicyConfigurationStateMachine = configurators.get(contextID);

        if (defaultPolicyConfigurationStateMachine == null) {
            return false;
        }

        return defaultPolicyConfigurationStateMachine.inService();
    }

    @Override
    public PolicyConfiguration getPolicyConfiguration(String contextID) {
        return configurators
                .get(contextID)
                .getPolicyConfiguration();
    }

    @Override
    public PolicyConfiguration getPolicyConfiguration() {
        String contextId = getContextID();
        if (contextId == null) {
            return null;
        }

        return getPolicyConfiguration(contextId);
    }

}