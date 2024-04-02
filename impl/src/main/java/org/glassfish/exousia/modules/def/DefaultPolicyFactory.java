/*
 * Copyright (c) 2023, 2024 Contributors to the Eclipse Foundation.
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

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyFactory;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DefaultPolicyFactory extends PolicyFactory {

    private static Map<String, Policy> idToPolicyMap = new ConcurrentHashMap<>();

    public DefaultPolicyFactory() {
        super(null);
    }

    // get/set global (system wide) policy?

    @Override
    public Policy getPolicy(String contextId) {
        if (contextId == null) {
            contextId = "__null___";
        }

        // TODO
        // if not present, instantiate from global property, set for this context id
        // Support old Policy if class is available in JVM?

        // TODO: draft code!
        Policy policy = idToPolicyMap.get(contextId);
        if (policy == null) {
            policy = idToPolicyMap.get("__null___");
            if (policy != null) {
                idToPolicyMap.put(contextId, policy);
            }
        }

        return policy;
    }

    @Override
    public void setPolicy(String contextId, Policy policy) {
        if (contextId == null) {
            contextId = "__null___";
        }

        // TODO: prevent to set if in use / after init phase
        // Jakarta Authentication doesn't do this, but Servlet does
        idToPolicyMap.put(contextId, policy);

    }

}
