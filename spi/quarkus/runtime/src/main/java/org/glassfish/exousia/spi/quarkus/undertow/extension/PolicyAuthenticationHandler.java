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

import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;

import org.glassfish.exousia.spi.quarkus.ExousiaConnector;

import static jakarta.servlet.DispatcherType.REQUEST;

/**
 * Makes authentication required for a request when the policy doesn't grant the requested resource to an
 * unauthenticated caller.
 *
 * <p>
 * Undertow decides whether authentication is required from its own constraints, before {@link ExousiaAuthorizationManager}
 * decides access. Without this, a resource the policy only grants to authenticated callers (for instance with a custom
 * policy) would get a 403 instead of an authentication challenge.
 */
public final class PolicyAuthenticationHandler implements HttpHandler {

    private final ExousiaConnector exousiaConnector;
    private final HttpHandler next;

    public PolicyAuthenticationHandler(ExousiaConnector exousiaConnector, HttpHandler next) {
        this.exousiaConnector = exousiaConnector;
        this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        SecurityContext securityContext = exchange.getSecurityContext();

        if (isAuthenticationRequired(servletRequestContext, securityContext)) {
            securityContext.setAuthenticationRequired();
        }

        next.handleRequest(exchange);
    }

    private boolean isAuthenticationRequired(ServletRequestContext servletRequestContext, SecurityContext securityContext) {
        return
            !isAnyNull(servletRequestContext, securityContext) &&
            servletRequestContext.getDispatcherType() == REQUEST &&
            !securityContext.isAuthenticationRequired() &&
            securityContext.getAuthenticatedAccount() == null &&
            !isPublic(servletRequestContext);

    }

    private boolean isPublic(ServletRequestContext servletRequestContext) {
        return
            exousiaConnector.getAuthorizationService()
                            .checkPublicWebResourcePermission(servletRequestContext.getOriginalRequest());

    }

    private static boolean isAnyNull(Object... values) {
        for (Object value : values) {
            if (value == null) {
                return true;
            }
        }

        return false;
    }
}
