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

package org.omnifaces.exousia;

import static org.omnifaces.exousia.constraints.transformer.ConstraintsToPermissionsTransformer.createResourceAndDataPermissions;
import static org.omnifaces.exousia.permissions.RolesToPermissionsTransformer.createWebRoleRefPermission;

import java.security.CodeSource;
import java.security.Permission;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.function.Supplier;

import javax.security.auth.Subject;

import org.omnifaces.exousia.constraints.SecurityConstraint;
import org.omnifaces.exousia.mapping.SecurityRoleRef;
import org.omnifaces.exousia.permissions.JakartaPermissions;
import org.omnifaces.exousia.spi.PrincipalMapper;

import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;
import jakarta.security.jacc.WebUserDataPermission;
import jakarta.servlet.http.HttpServletRequest;

/**
 *
 * @author Arjan Tijms
 */
public class AuthorizationService {

    public static final String HTTP_SERVLET_REQUEST = "jakarta.servlet.http.HttpServletRequest";
    public static final String SUBJECT = "javax.security.auth.Subject.container";

    public static final String FACTORY = "jakarta.security.jacc.PolicyConfigurationFactory.provider";

    public static final String PRINCIPAL_MAPPER = "jakarta.authorization.PrincipalMapper.provider";

    /**
     * The authorization policy. This is the class that makes the actual decision for a permission
     * request.
     */
    private final Policy policy;

    private final PolicyConfigurationFactory factory;

    private final PolicyConfiguration policyConfiguration;

    private final CodeSource emptyCodeSource = new CodeSource(null, (Certificate[]) null);

    private final ProtectionDomain emptyProtectionDomain = newProtectionDomain(null);

    public AuthorizationService(
            Class<?> factoryClass, Class<? extends Policy> policyClass, String contextId,
            Supplier<HttpServletRequest> requestSupplier,
            Supplier<Subject> subjectSupplier) {
        this(factoryClass, policyClass, contextId, requestSupplier, subjectSupplier, null);
    }

    public AuthorizationService(
            Class<?> factoryClass, Class<? extends Policy> policyClass, String contextId,
            Supplier<HttpServletRequest> requestSupplier,
            Supplier<Subject> subjectSupplier, PrincipalMapper principalMapper) {
        try {

            // Install the authorization factory
            System.setProperty(FACTORY, factoryClass.getName());
            factory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
            policyConfiguration = factory.getPolicyConfiguration(contextId, false);

            // Install the authorization policy
            Policy.setPolicy(policyClass.newInstance());
            policy = Policy.getPolicy();

            // Sets the context Id (aka application Id), which may be used by authorization modules to get the right
            // authorization config
            PolicyContext.setContextID(contextId);

            // Sets the handlers (aka suppliers) for the request and subject for the current thread
            PolicyContext.registerHandler(
                HTTP_SERVLET_REQUEST,
                new DefaultPolicyContextHandler(HTTP_SERVLET_REQUEST, requestSupplier),
                true);

            PolicyContext.registerHandler(
                SUBJECT,
                new DefaultPolicyContextHandler(SUBJECT, subjectSupplier),
                true);

            PolicyContext.registerHandler(
                PRINCIPAL_MAPPER,
                new DefaultPolicyContextHandler(PRINCIPAL_MAPPER, () -> principalMapper),
                true);

        } catch (IllegalAccessException | InstantiationException | PolicyContextException | ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    public void addConstraintsToPolicy(List<SecurityConstraint> securityConstraints, Set<String> declaredRoles, boolean isDenyUncoveredHttpMethods, Map<String, List<SecurityRoleRef>> servletRoleMappings) {
        try {
            JakartaPermissions jakartaPermissions = createResourceAndDataPermissions(declaredRoles, isDenyUncoveredHttpMethods, securityConstraints);

            // Add the translated/generated excluded permissions
            policyConfiguration.addToExcludedPolicy(jakartaPermissions.getExcluded());

            // Add the translated/generated unchecked permissions
            policyConfiguration.addToUncheckedPolicy(jakartaPermissions.getUnchecked());

            // Add the translated/generated per role resource permissions
            for (Entry<String, Permissions> roleEntry : jakartaPermissions.getPerRole().entrySet()) {
                policyConfiguration.addToRole(roleEntry.getKey(), roleEntry.getValue());
            }

            Map<String, Permissions> roleRefPermissions = createWebRoleRefPermission(declaredRoles, servletRoleMappings);

            // Add the translated/generated per role role-ref permissions
            for (Entry<String, Permissions> roleEntry : roleRefPermissions.entrySet()) {
                policyConfiguration.addToRole(roleEntry.getKey(), roleEntry.getValue());
            }

            // TEMP TEMP TEMP!
            policyConfiguration.commit();

        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }

    }

    public PolicyConfiguration getPolicyConfiguration() {
        return policyConfiguration;
    }

    public boolean checkWebUserDataPermission(HttpServletRequest request) {
        return checkPermission(new WebUserDataPermission(request));
    }

    public boolean checkPublicWebResourcePermission(HttpServletRequest request) {
        return checkPermission(new WebResourcePermission(getConstrainedURI(request), request.getMethod()));
    }

    public boolean checkWebResourcePermission(HttpServletRequest request) {
        try {
            Subject subject = (Subject) PolicyContext.getContext(SUBJECT);

            return checkPermission(
                    new WebResourcePermission(
                        getConstrainedURI(request), request.getMethod()), subject.getPrincipals());
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean checkWebRoleRefPermission(String servletName, String role) {
        try {
            Subject subject = (Subject) PolicyContext.getContext(SUBJECT);

            return checkPermission(
                    new WebRoleRefPermission(servletName, role),
                    subject.getPrincipals());
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    boolean checkPermission(Permission permissionToBeChecked) {
        return policy.implies(emptyProtectionDomain, permissionToBeChecked);
    }

    boolean checkPermission(Permission permissionToBeChecked, Set<Principal> principals) {
        return policy.implies(newProtectionDomain(principals), permissionToBeChecked);
    }

    private ProtectionDomain newProtectionDomain(Set<Principal> principalSet) {
        return new ProtectionDomain(
                emptyCodeSource,
                null,
                null,
                principalSet == null ? null : (Principal[]) principalSet.toArray(new Principal[0]));
    }

    private String getConstrainedURI(HttpServletRequest request) {
        String relativeURI = getRequestRelativeURI(request);
        if (relativeURI.equals("/")) {
            return "";
        }

        return relativeURI.replaceAll(":", "%3A");
    }

    private String getRequestRelativeURI(HttpServletRequest request) {
        return request.getRequestURI().substring(request.getContextPath().length());
    }

}
