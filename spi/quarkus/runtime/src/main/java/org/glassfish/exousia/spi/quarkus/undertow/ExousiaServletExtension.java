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
package org.glassfish.exousia.spi.quarkus.undertow;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.HttpMethodSecurityInfo;
import io.undertow.servlet.api.ListenerInfo;
import io.undertow.servlet.api.SecurityInfo;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.ServletSecurityInfo;
import io.undertow.servlet.util.ImmediateInstanceFactory;

import jakarta.servlet.ServletContext;
import jakarta.servlet.annotation.ServletSecurity.TransportGuarantee;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.glassfish.exousia.constraints.SecurityConstraint;
import org.glassfish.exousia.constraints.WebResourceCollection;
import org.glassfish.exousia.mapping.SecurityRoleRef;
import org.glassfish.exousia.spi.quarkus.ExousiaConnector;
import org.glassfish.exousia.spi.quarkus.jakarta.PolicyInitializationListener;
import org.glassfish.exousia.spi.quarkus.undertow.extension.ExousiaAuthorizationManager;
import org.glassfish.exousia.spi.quarkus.undertow.extension.PolicyAuthenticationHandler;
import org.glassfish.exousia.spi.quarkus.undertow.extension.PolicyContextIdSetup;

import static io.undertow.servlet.api.SecurityInfo.EmptyRoleSemantic.AUTHENTICATE;
import static io.undertow.servlet.api.SecurityInfo.EmptyRoleSemantic.DENY;
import static io.undertow.servlet.api.TransportGuaranteeType.CONFIDENTIAL;
import static io.undertow.servlet.api.TransportGuaranteeType.INTEGRAL;
import static java.util.Collections.emptySet;

/**
 * Integrates Exousia (Jakarta Authorization) into the Undertow based Servlet container of Quarkus.
 *
 * <p>
 * Undertow lets an {@link io.undertow.servlet.api.AuthorizationManager} make the access decisions for a deployment. This
 * extension installs {@link ExousiaAuthorizationManager}, which asks the Jakarta Authorization policy, and fills that
 * policy with the security constraints Undertow collected (web.xml, annotations and programmatic), the same way the
 * Tomcat integration does.
 *
 * @author Arjan Tijms
 */
public class ExousiaServletExtension implements ServletExtension {

    /** The role Jakarta Authorization uses for "any authenticated caller". */
    private static final String ANY_AUTHENTICATED_CALLER_ROLE = "**";

    /**
     * The roles the application declares (security-role in web.xml, and @DeclareRoles). Quarkus collects these, but
     * doesn't pass them on to Undertow, so they are passed in at build time.
     */
    private Set<String> securityRoles = new HashSet<>();

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
        deploymentInfo.addSecurityRoles(securityRoles);

        // Provides a connection to the Exousia services for this servlet context
        ExousiaConnector exousiaConnector = new ExousiaConnector(servletContext);

        // Sets the context ID (the application's identifier for Jakarta Authorization) for every request and every call
        // into the application, such as Servlet container initializers and listeners
        deploymentInfo.addThreadSetupAction(new PolicyContextIdSetup(exousiaConnector));

        // Makes the policy decide access to resources, roles (isUserInRole) and the transport guarantee
        deploymentInfo.setAuthorizationManager(new ExousiaAuthorizationManager(exousiaConnector));

        // Makes the policy decide whether a request needs authentication
        deploymentInfo.addSecurityWrapper(next -> new PolicyAuthenticationHandler(exousiaConnector, next));

        // Copies the security constraints to the policy and commits it, after the application has initialized (Servlet
        // container initializers may add constraints programmatically)
        deploymentInfo.addListener(new ListenerInfo(
            PolicyInitializationListener.class,
            new ImmediateInstanceFactory<>(new PolicyInitializationListener(exousiaConnector, deploymentInfo))));
    }

    /**
     * Transforms the security constraints (web.xml, annotations, and programmatic) from the Undertow types to Exousia types.
     *
     * <p>
     * Undertow keeps the constraints from <code>@ServletSecurity</code> and
     * <code>ServletRegistration.Dynamic#setServletSecurity</code> with the Servlet, and only turns them into constraints
     * for its own use. They are converted here the same way: for the Servlet's mappings that no other constraint covers.
     *
     * @param deploymentInfo the deployment holding the Undertow constraints
     * @return the equivalent Exousia constraints
     */
    public static List<SecurityConstraint> convertUndertowConstraintsToExousia(DeploymentInfo deploymentInfo) {
        List<SecurityConstraint> exousiaConstraints = new ArrayList<>();
        Set<String> urlPatterns = new HashSet<>();

        for (io.undertow.servlet.api.SecurityConstraint undertowConstraint : deploymentInfo.getSecurityConstraints()) {
            List<WebResourceCollection> exousiaWebResourceCollections = new ArrayList<>();
            for (io.undertow.servlet.api.WebResourceCollection undertowWebResourceCollection : undertowConstraint.getWebResourceCollections()) {
                exousiaWebResourceCollections.add(new WebResourceCollection(
                    undertowWebResourceCollection.getUrlPatterns(),
                    undertowWebResourceCollection.getHttpMethods(),
                    undertowWebResourceCollection.getHttpMethodOmissions()));

                urlPatterns.addAll(undertowWebResourceCollection.getUrlPatterns());
            }

            exousiaConstraints.add(new SecurityConstraint(
                exousiaWebResourceCollections,
                getRolesAllowed(undertowConstraint),
                getTransportGuarantee(undertowConstraint)));
        }

        for (ServletInfo servlet : deploymentInfo.getServlets().values()) {
            ServletSecurityInfo servletSecurity = servlet.getServletSecurityInfo();
            if (servletSecurity == null) {
                continue;
            }

            Set<String> mappings = new HashSet<>(servlet.getMappings());
            mappings.removeAll(urlPatterns);
            if (mappings.isEmpty()) {
                continue;
            }

            // The constraints for specific HTTP methods (@HttpMethodConstraint)
            Set<String> methods = new HashSet<>();
            for (HttpMethodSecurityInfo methodSecurity : servletSecurity.getHttpMethodSecurityInfo()) {
                methods.add(methodSecurity.getMethod());

                exousiaConstraints.add(new SecurityConstraint(
                    List.of(new WebResourceCollection(mappings, Set.of(methodSecurity.getMethod()), emptySet())),
                    getRolesAllowed(methodSecurity),
                    getTransportGuarantee(methodSecurity)));
            }

            // The constraint for all other HTTP methods (@HttpConstraint)
            exousiaConstraints.add(new SecurityConstraint(
                List.of(new WebResourceCollection(mappings, emptySet(), methods)),
                getRolesAllowed(servletSecurity),
                getTransportGuarantee(servletSecurity)));
        }

        return exousiaConstraints;
    }

    public Set<String> getSecurityRoles() {
        return securityRoles;
    }

    public void setSecurityRoles(Set<String> securityRoles) {
        this.securityRoles = securityRoles;
    }

    /**
     * @return all roles the application declares, explicitly or by using them in a constraint
     */
    public static Set<String> collectDeclaredRoles(DeploymentInfo deploymentInfo) {
        Set<String> declaredRoles = new HashSet<>(deploymentInfo.getSecurityRoles());

        for (io.undertow.servlet.api.SecurityConstraint undertowConstraint : deploymentInfo.getSecurityConstraints()) {
            declaredRoles.addAll(undertowConstraint.getRolesAllowed());
        }

        for (ServletInfo servlet : deploymentInfo.getServlets().values()) {
            ServletSecurityInfo servletSecurity = servlet.getServletSecurityInfo();
            if (servletSecurity != null) {
                declaredRoles.addAll(servletSecurity.getRolesAllowed());
                for (HttpMethodSecurityInfo methodSecurity : servletSecurity.getHttpMethodSecurityInfo()) {
                    declaredRoles.addAll(methodSecurity.getRolesAllowed());
                }
            }
        }

        return declaredRoles;
    }

    /**
     * @return the security role references (security-role-ref) per Servlet name, for all Servlets
     */
    public static Map<String, List<SecurityRoleRef>> getServletRoleMappings(DeploymentInfo deploymentInfo) {
        Map<String, List<SecurityRoleRef>> servletRoleMappings = new HashMap<>();

        for (ServletInfo servlet : deploymentInfo.getServlets().values()) {
            List<SecurityRoleRef> roleRefs = new ArrayList<>();
            for (io.undertow.servlet.api.SecurityRoleRef undertowRoleRef : servlet.getSecurityRoleRefs()) {
                roleRefs.add(new SecurityRoleRef(undertowRoleRef.getRole(), undertowRoleRef.getLinkedRole()));
            }

            servletRoleMappings.put(servlet.getName(), roleRefs);
        }

        return servletRoleMappings;
    }

    /**
     * Exousia uses null for no auth constraint (unchecked, everyone has access), an empty set for an empty auth
     * constraint (excluded, nobody has access), and "**" for any authenticated caller. Undertow uses the empty role
     * semantic for these.
     *
     * <p>
     * Note that Quarkus maps the role "*" (all roles the application declares) to "any authenticated caller" as well.
     */
    private static Set<String> getRolesAllowed(SecurityInfo<?> securityInfo) {
        if (!securityInfo.getRolesAllowed().isEmpty()) {
            return new HashSet<>(securityInfo.getRolesAllowed());
        }

        if (securityInfo.getEmptyRoleSemantic() == DENY) {
            return emptySet();
        }

        if (securityInfo.getEmptyRoleSemantic() == AUTHENTICATE) {
            return Set.of(ANY_AUTHENTICATED_CALLER_ROLE);
        }

        return null;
    }

    private static TransportGuarantee getTransportGuarantee(SecurityInfo<?> securityInfo) {
        return
            securityInfo.getTransportGuaranteeType() == CONFIDENTIAL || securityInfo.getTransportGuaranteeType() == INTEGRAL
                ? TransportGuarantee.CONFIDENTIAL
                : TransportGuarantee.NONE;
    }
}
