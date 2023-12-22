/*
 * Copyright (c) 2023 Contributors to the Eclipse Foundation.
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

package org.glassfish.exousia;

import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PolicyContextHandler;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultPolicyContextHandler implements PolicyContextHandler {

    private static Map<String, Map<String, Supplier<? extends Object>>> handlers = new ConcurrentHashMap<>();

    public static void removeAllForContextId(String contextId) {
        handlers.remove(contextId);
    }

    public DefaultPolicyContextHandler(String contextId, String key, Supplier<? extends Object> contextObjectSupplier) {
        handlers.computeIfAbsent(contextId, e -> new ConcurrentHashMap<>())
                .computeIfAbsent(key, e -> contextObjectSupplier);

    }

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        return handlers.get(PolicyContext.getContextID()).get(key).get();
    }

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return handlers.get(PolicyContext.getContextID()).containsKey(key);
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return handlers.get(PolicyContext.getContextID()).keySet().toArray(String[]::new);
    }

}
