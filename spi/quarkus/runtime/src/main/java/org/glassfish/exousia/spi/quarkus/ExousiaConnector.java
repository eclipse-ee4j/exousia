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
package org.glassfish.exousia.spi.quarkus;

import io.quarkus.arc.Arc;
import io.quarkus.arc.ArcContainer;
import io.quarkus.arc.InstanceHandle;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.SecurityIdentity;
import io.undertow.security.api.SecurityContext;
import io.undertow.servlet.handlers.ServletRequestContext;

import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyFactory;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

import javax.security.auth.Subject;

import org.glassfish.exousia.AuthorizationService;
import org.glassfish.exousia.modules.def.DefaultPolicy;
import org.glassfish.exousia.modules.def.DefaultPolicyConfigurationFactory;
import org.glassfish.exousia.modules.def.DefaultPolicyFactory;
import org.glassfish.exousia.spi.quarkus.jakarta.AccountPrincipalMapper;

/**
 * This class provides access to the Exousia AuthorizationService and its managed contextId.
 *
 * <p>
 * The context ID and the {@link AuthorizationService} are created on first use, which is after all Servlet extensions
 * ran: the context ID contains the virtual server name, which another extension (such as the Epicyro one for Jakarta
 * Authentication) may set.
 */
public final class ExousiaConnector {

    private final ServletContext servletContext;

    private volatile String contextId;
    private volatile AuthorizationService authorizationService;

    public ExousiaConnector(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    /**
     * @return the context ID of the application: its virtual server name and context path
     */
    public String getContextId() {
        String id = contextId;
        if (id == null) {
            id = contextId = AuthorizationService.getServletContextId(servletContext);
        }

        return id;
    }

    public AuthorizationService getAuthorizationService() {
        AuthorizationService service = authorizationService;
        if (service == null) {
            synchronized (this) {
                service = authorizationService;
                if (service == null) {
                    service = authorizationService = createAuthorizationService();
                }
            }
        }

        return service;
    }

    private AuthorizationService createAuthorizationService() {
        installDefaults();
        installApplicationFactories();

        // Uses the installed factories, so that an application (or a test suite) can configure its own
        AuthorizationService service = new AuthorizationService(
            getContextId(),
            ExousiaConnector::getCurrentSubject,
            AccountPrincipalMapper::new);

        service.setRequestSupplier(getContextId(), ExousiaConnector::getCurrentRequest);

        return service;
    }

    /**
     * Installs the policy configuration factory and policy factory the application configures with the context
     * parameters {@value PolicyConfigurationFactory#FACTORY_NAME} and {@value PolicyFactory#FACTORY_NAME}. They wrap
     * the ones installed before, when they have a constructor that takes those.
     */
    private void installApplicationFactories() {
        Class<?> policyConfigurationFactoryClass = loadApplicationClass(servletContext.getInitParameter(PolicyConfigurationFactory.FACTORY_NAME));
        if (policyConfigurationFactoryClass != null) {
            AuthorizationService.installPolicyConfigurationFactory(policyConfigurationFactoryClass);
        }

        Class<?> policyFactoryClass = loadApplicationClass(servletContext.getInitParameter(PolicyFactory.FACTORY_NAME));
        if (policyFactoryClass != null) {
            AuthorizationService.installPolicyFactory(policyFactoryClass);
        }
    }

    private Class<?> loadApplicationClass(String className) {
        if (className == null || className.isBlank()) {
            return null;
        }

        try {
            return Class.forName(className.trim(), true, servletContext.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Cannot load the Jakarta Authorization factory " + className, e);
        }
    }

    /**
     * Installs Exousia's policy configuration factory, policy factory and policy, unless others have been configured.
     */
    private static void installDefaults() {
        if (System.getProperty(PolicyConfigurationFactory.FACTORY_NAME) == null) {
            System.setProperty(PolicyConfigurationFactory.FACTORY_NAME, DefaultPolicyConfigurationFactory.class.getName());
        }

        if (System.getProperty(PolicyFactory.FACTORY_NAME) == null) {
            System.setProperty(PolicyFactory.FACTORY_NAME, DefaultPolicyFactory.class.getName());
        }

        // The policy for all applications (context ID null), unless one has been set
        PolicyFactory policyFactory = PolicyFactory.getPolicyFactory();
        if (policyFactory.getPolicy(null) == null) {
            policyFactory.setPolicy(null, new DefaultPolicy());
        }
    }

    /**
     * The caller is Quarkus' current identity, when it's authenticated: Undertow authenticates it, but code may switch
     * to another identity for a while, such as to run an Enterprise Bean as its run-as role. Otherwise it's the account
     * Undertow authenticated, which Quarkus may not know (such as one restored from a registered session).
     *
     * <p>
     * Outside a request, such as in a listener at startup, there's no caller, and Quarkus' identity isn't asked for: that
     * would create Quarkus' identity providers, and those of Elytron would keep a security domain that isn't there yet.
     *
     * @return the Subject of the current caller, which is empty if the caller is not authenticated, or null outside a
     *         request
     */
    static Subject getCurrentSubject() {
        ServletRequestContext servletRequestContext = ServletRequestContext.current();
        if (servletRequestContext == null) {
            return null;
        }

        SecurityIdentity identity = getCurrentIdentity();
        if (identity != null && !identity.isAnonymous()) {
            return AccountPrincipalMapper.toSubject(identity.getPrincipal(), identity.getRoles());
        }

        SecurityContext securityContext = servletRequestContext.getExchange().getSecurityContext();

        return AccountPrincipalMapper.toSubject(securityContext == null ? null : securityContext.getAuthenticatedAccount());
    }

    private static SecurityIdentity getCurrentIdentity() {
        // The identity association is request scoped
        ArcContainer container = Arc.container();
        if (container == null || !container.requestContext().isActive()) {
            return null;
        }

        InstanceHandle<CurrentIdentityAssociation> identityAssociation = container.instance(CurrentIdentityAssociation.class);

        return identityAssociation.isAvailable() ? identityAssociation.get().getIdentity() : null;
    }

    static HttpServletRequest getCurrentRequest() {
        ServletRequestContext servletRequestContext = ServletRequestContext.current();

        return servletRequestContext == null ? null : servletRequestContext.getOriginalRequest();
    }
}
