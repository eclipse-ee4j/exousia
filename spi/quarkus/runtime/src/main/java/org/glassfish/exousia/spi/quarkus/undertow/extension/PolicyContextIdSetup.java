/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
package org.glassfish.exousia.spi.quarkus.undertow.extension;

import io.undertow.servlet.api.ThreadSetupHandler;

import jakarta.security.jacc.PolicyContext;

import org.glassfish.exousia.spi.quarkus.ExousiaConnector;

/**
 * Sets the Jakarta Authorization context ID of the application on the current thread while Undertow calls into the
 * application: for requests, but also for Servlet container initializers and listeners. The policy, and for instance
 * {@link jakarta.security.jacc.PolicyFactory#getPolicy()}, use it to find the application's policy.
 *
 * <p>
 * It also makes sure the authorization service exists before the first call into the application, as that installs
 * the default Jakarta Authorization factories and policy, which the application may use (e.g. to decorate the policy).
 */
public final class PolicyContextIdSetup implements ThreadSetupHandler {

    private final ExousiaConnector exousiaConnector;

    public PolicyContextIdSetup(ExousiaConnector exousiaConnector) {
        this.exousiaConnector = exousiaConnector;
    }

    @Override
    public <T, C> Action<T, C> create(Action<T, C> action) {
        return (exchange, context) -> {
            exousiaConnector.getAuthorizationService();

            String previousContextId = PolicyContext.getContextID();
            PolicyContext.setContextID(exousiaConnector.getContextId());
            try {
                return action.call(exchange, context);
            } finally {
                PolicyContext.setContextID(previousContextId);
            }
        };
    }
}
