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
package org.glassfish.exousia.spi.quarkus.vertx;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.undertow.runtime.ServletHttpSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Singleton;

import org.glassfish.exousia.spi.quarkus.undertow.extension.ExousiaAuthorizationManager;

/**
 * Replaces Quarkus' Servlet security policy, which enforces the Servlet security constraints with Undertow's role
 * checks before a request reaches Undertow. With Exousia the Jakarta Authorization policy decides, in Undertow (see
 * {@link ExousiaAuthorizationManager}), and may decide differently.
 */
@Singleton
public class ExousiaServletHttpSecurityPolicy extends ServletHttpSecurityPolicy {

    @Override
    public Uni<CheckResult> checkPermission(RoutingContext request, Uni<SecurityIdentity> identity, HttpSecurityPolicy.AuthorizationRequestContext requestContext) {
        return CheckResult.permit();
    }
}
