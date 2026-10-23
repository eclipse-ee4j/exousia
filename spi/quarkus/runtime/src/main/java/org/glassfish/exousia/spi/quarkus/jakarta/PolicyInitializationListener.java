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
package org.glassfish.exousia.spi.quarkus.jakarta;

import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.ServletInfo;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.glassfish.exousia.AuthorizationService;
import org.glassfish.exousia.spi.quarkus.ExousiaConnector;
import org.glassfish.exousia.spi.quarkus.undertow.ExousiaServletExtension;

import static org.glassfish.exousia.spi.quarkus.undertow.ExousiaServletExtension.collectDeclaredRoles;
import static org.glassfish.exousia.spi.quarkus.undertow.ExousiaServletExtension.convertUndertowConstraintsToExousia;
import static org.glassfish.exousia.spi.quarkus.undertow.ExousiaServletExtension.getServletRoleMappings;

/**
 * Puts the application's security constraints in its policy and commits the policy, which takes it into service.
 * The constraints are then removed from Undertow, so the policy alone decides.
 *
 * <p>
 * Added by {@link ExousiaServletExtension} as the last listener, so it runs after the Servlet container initializers
 * and the application's own listeners have registered Servlets and constraints.
 */
public final class PolicyInitializationListener implements ServletContextListener {

    private final ExousiaConnector exousiaConnector;
    private final DeploymentInfo deploymentInfo;

    public PolicyInitializationListener(ExousiaConnector deployment, DeploymentInfo deploymentInfo) {
        this.exousiaConnector = deployment;
        this.deploymentInfo = deploymentInfo;
    }

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        AuthorizationService authorizationService = exousiaConnector.getAuthorizationService();

        authorizationService.addConstraintsToPolicy(
            convertUndertowConstraintsToExousia(deploymentInfo),
            collectDeclaredRoles(deploymentInfo),
            deploymentInfo.isDenyUncoveredHttpMethods(),
            getServletRoleMappings(deploymentInfo));

        authorizationService.commitPolicy();

        // Undertow builds its security handlers after the listeners ran. Without constraints it doesn't install its
        // constraint handlers, which would for instance require authentication for a resource that a (custom) policy
        // grants to everyone. The policy now decides about authentication (PolicyAuthenticationHandler), access and the
        // transport guarantee (ExousiaAuthorizationManager).
        deploymentInfo.getSecurityConstraints().clear();
        for (ServletInfo servlet : deploymentInfo.getServlets().values()) {
            servlet.setServletSecurityInfo(null);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        exousiaConnector.getAuthorizationService().deletePolicy();
    }
}
