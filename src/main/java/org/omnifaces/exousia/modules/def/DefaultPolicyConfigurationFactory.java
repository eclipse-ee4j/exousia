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
package org.omnifaces.exousia.modules.def;

import static javax.security.jacc.PolicyContext.getContextID;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;

/**
 * 
 * @author Arjan Tijms
 */
public class DefaultPolicyConfigurationFactory extends PolicyConfigurationFactory {
     
    private static final ConcurrentMap<String, DefaultPolicyConfigurationStateMachine> configurators = new ConcurrentHashMap<>();
 
    @Override
    public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
         
        if (!configurators.containsKey(contextID)) {
            configurators.putIfAbsent(contextID, new DefaultPolicyConfigurationStateMachine(new DefaultPolicyConfiguration(contextID)));
        }
         
        DefaultPolicyConfigurationStateMachine defaultPolicyConfigurationStateMachine = configurators.get(contextID);
         
        if (remove) {
            defaultPolicyConfigurationStateMachine.delete();
        }
         
        // According to the contract of getPolicyConfiguration() every PolicyConfiguration returned from here
        // should always be transitioned to the OPEN state.
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
     
    public static DefaultPolicyConfiguration getCurrentPolicyConfiguration() {
        return (DefaultPolicyConfiguration) configurators.get(getContextID()).getPolicyConfiguration();
    }
     
}