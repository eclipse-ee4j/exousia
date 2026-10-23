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

import io.undertow.security.idm.Account;
import io.undertow.servlet.api.AuthorizationManager;
import io.undertow.servlet.api.Deployment;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.SingleConstraintMatch;
import io.undertow.servlet.api.TransportGuaranteeType;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

import org.glassfish.exousia.spi.quarkus.ExousiaConnector;
import org.glassfish.exousia.spi.quarkus.jakarta.AccountPrincipalMapper;
import org.glassfish.exousia.spi.quarkus.undertow.ExousiaServletExtension;

import static io.undertow.servlet.api.TransportGuaranteeType.CONFIDENTIAL;
import static io.undertow.servlet.api.TransportGuaranteeType.REJECTED;

/**
 * Lets the Jakarta Authorization policy make Undertow's access decisions, instead of Undertow's own role checks.
 *
 * <p>
 * The constraints Undertow matched for a request are not used: the policy contains the same constraints (see
 * {@link ExousiaServletExtension#convertUndertowConstraintsToExousia}), and a custom policy may decide differently.
 *
 * @author Arjan Tijms
 */
public class ExousiaAuthorizationManager implements AuthorizationManager {

    private final ExousiaConnector exousiaConnector;

    public ExousiaAuthorizationManager(ExousiaConnector exousiaConnector) {
        this.exousiaConnector = exousiaConnector;
    }

    /**
     * Checks the WebRoleRefPermission, for {@link HttpServletRequest#isUserInRole(String)}.
     */
    @Override
    public boolean isUserInRole(String roleName, Account account, ServletInfo servletInfo, HttpServletRequest request, Deployment undertowDeployment) {
        return exousiaConnector.getAuthorizationService().checkWebRoleRefPermission(
            servletInfo == null ? "" : servletInfo.getName(),
            roleName,
            AccountPrincipalMapper.toSubject(account));
    }

    /**
     * Checks the WebResourcePermission for the requested resource. Undertow calls this after authentication, and sends a
     * 403 when it returns false.
     */
    @Override
    public boolean canAccessResource(List<SingleConstraintMatch> constraints, Account account, ServletInfo servletInfo, HttpServletRequest request, Deployment undertowDeployment) {
        return exousiaConnector.getAuthorizationService().checkWebResourcePermission(
            request,
            AccountPrincipalMapper.toSubject(account));
    }

    /**
     * Checks the WebUserDataPermission for the requested resource over the current connection. If that's not granted
     * but would be over a confidential connection, the request needs a confidential connection (Undertow redirects to
     * the confidential port), otherwise it is rejected.
     */
    @Override
    public TransportGuaranteeType transportGuarantee(TransportGuaranteeType currentConnectionGuarantee, TransportGuaranteeType configuredRequiredGuarantee, HttpServletRequest request) {
        if (exousiaConnector.getAuthorizationService().checkWebUserDataPermission(request)) {
            return currentConnectionGuarantee;
        }

        if (!request.isSecure()
            && exousiaConnector.getAuthorizationService().checkWebUserDataPermission(getURLPattern(request), request.getMethod(), true)) {
            return CONFIDENTIAL;
        }

        return REJECTED;
    }

    /**
     * @return the request URI relative to the context path, in the form a URLPattern of a Jakarta Authorization
     *         permission uses
     */
    private static String getURLPattern(HttpServletRequest request) {
        String relativeURI = request.getRequestURI().substring(request.getContextPath().length());
        if (relativeURI.equals("/")) {
            return "";
        }

        return relativeURI.replace(":", "%3A");
    }
}
