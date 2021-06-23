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

package org.glassfish.exousia;

import static java.util.logging.Level.FINE;
import static org.glassfish.exousia.constraints.transformer.ConstraintsToPermissionsTransformer.createResourceAndDataPermissions;
import static org.glassfish.exousia.permissions.RolesToPermissionsTransformer.createWebRoleRefPermission;

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
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.glassfish.exousia.constraints.SecurityConstraint;
import org.glassfish.exousia.constraints.transformer.ConstraintsToPermissionsTransformer;
import org.glassfish.exousia.mapping.SecurityRoleRef;
import org.glassfish.exousia.modules.def.DefaultPolicy;
import org.glassfish.exousia.modules.def.DefaultPolicyConfigurationFactory;
import org.glassfish.exousia.permissions.JakartaPermissions;
import org.glassfish.exousia.spi.PrincipalMapper;

import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;
import jakarta.security.jacc.WebUserDataPermission;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

/**
 *
 * @author Arjan Tijms
 */
public class AuthorizationService {

    static final Logger logger = Logger.getLogger(ConstraintsToPermissionsTransformer.class.getName());

    public static final String HTTP_SERVLET_REQUEST = "jakarta.servlet.http.HttpServletRequest";
    public static final String SUBJECT = "javax.security.auth.Subject.container";
    public static final String FACTORY = "jakarta.security.jacc.PolicyConfigurationFactory.provider";
    public static final String PRINCIPAL_MAPPER = "jakarta.authorization.PrincipalMapper.provider";

    private final String contextId;

    /**
     * The authorization policy. This is the class that makes the actual decision for a permission
     * request.
     */
    private final Policy policy;
    private final PolicyConfigurationFactory factory;
    private final PolicyConfiguration policyConfiguration;

    private final CodeSource emptyCodeSource = new CodeSource(null, (Certificate[]) null);
    private final ProtectionDomain emptyProtectionDomain = newProtectionDomain(null);

    private String constrainedUriRequestAttribute;

    public AuthorizationService(
            ServletContext servletContext,
            Supplier<HttpServletRequest> requestSupplier,
            Supplier<Subject> subjectSupplier) {
        this(
            DefaultPolicyConfigurationFactory.class,
            DefaultPolicy.class,
            getServletContextId(servletContext), requestSupplier, subjectSupplier);
    }

    public AuthorizationService(
            String contextId,
            Supplier<HttpServletRequest> requestSupplier,
            Supplier<Subject> subjectSupplier) {
        this(
            DefaultPolicyConfigurationFactory.class,
            DefaultPolicy.class,
            contextId, requestSupplier, subjectSupplier);
    }

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

        this(
            installFactory(factoryClass), installPolicy(policyClass), contextId,
            requestSupplier,
            subjectSupplier, principalMapper);
    }

    public AuthorizationService(
        String contextId,
        Supplier<HttpServletRequest> requestSupplier,
        Supplier<Subject> subjectSupplier, PrincipalMapper principalMapper) {

    this(
        getFactory(), getPolicy(), contextId,
        requestSupplier,
        subjectSupplier, principalMapper);
}

    public AuthorizationService(
        PolicyConfigurationFactory factory, Policy policy, String contextId,
        Supplier<HttpServletRequest> requestSupplier,
        Supplier<Subject> subjectSupplier, PrincipalMapper principalMapper) {
        try {
            this.factory = factory;
            this.policyConfiguration = factory.getPolicyConfiguration(contextId, false);
            this.policy = Policy.getPolicy();
            this.contextId = contextId;


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

        } catch (PolicyContextException | IllegalArgumentException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * @return the constrainedUriRequestAttribute
     */
    public String getConstrainedUriRequestAttribute() {
        return constrainedUriRequestAttribute;
    }

    /**
     * @param constrainedUriRequestAttribute the constrainedUriRequestAttribute to set
     */
    public void setConstrainedUriRequestAttribute(String constrainedUriRequestAttribute) {
        this.constrainedUriRequestAttribute = constrainedUriRequestAttribute;
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

        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }

    }

    public void removeStatementsFromPolicy(Set<String> declaredRoles) {
        try {
            boolean inService = factory.inService(contextId);

            policyConfiguration.removeUncheckedPolicy();
            policyConfiguration.removeExcludedPolicy();

            if (declaredRoles != null) {
                // Remove roles one by one for policy configurations which don't support
                // the "*" role.
                for (String role : declaredRoles) {
                    policyConfiguration.removeRole(role);
                }
            }

            // 1st call will remove "*" role if present.
            policyConfiguration.removeRole("*");

            // 2nd will remove all roles (if supported).
            policyConfiguration.removeRole("*");

            // Refresh policy if the context was in service
            if (inService) {
                policy.refresh();
            }
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * This method obtains the policy configuration object corresponding to the name, and links it, for roleMapping purposes
     * to another. If the policy configuration is already InService when this method is called, this method does nothing.
     *
     * @param String contextId - the module id which serves to identify the corresponding policy context. The name shall not be
     * null.
     * @param String linkedContextId - the module id of the module being linked to this context. This value may be null, in which
     * case, no link is done, but the inService state of the named PC is returned.
     * @param boolean lastInService - the inService state returned by the previous call to this method. The value of this
     * argument is only significant when linkName is not null.
     *
     * @return boolean if linkedContextId is null, returns the inService state of the policy configuration identified in the contextId
     * argument. Otherwise returns the value passed to lastInService.
     */
    public boolean linkPolicy(String linkedContextId, boolean lastInService) {
        try {
            boolean inService = factory.inService(contextId);

            if (linkedContextId == null) {
                return inService;
            }

            if (inService != lastInService) {
                throw new IllegalStateException("Inconsistent Module State");
            }

            // Only do the link if the named policyConfiguration is not inService.
            if (!inService) {
                PolicyConfiguration policyConfiguration = factory.getPolicyConfiguration(contextId, false);
                PolicyConfiguration linkedPolicyConfiguration = factory.getPolicyConfiguration(linkedContextId, false);
                policyConfiguration.linkConfiguration(linkedPolicyConfiguration);
            }

            return lastInService;

        } catch (PolicyContextException pce) {
            throw new IllegalStateException(pce.toString());
        }
    }

    public static boolean linkPolicy(String contextId, String linkedContextId, boolean lastInService) {
        try {
            PolicyConfigurationFactory factory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

            boolean inService = factory.inService(contextId);

            if (linkedContextId == null) {
                return inService;
            }

            if (inService != lastInService) {
                throw new IllegalStateException("Inconsistent Module State");
            }

            // Only do the link if the named policyConfiguration is not inService.
            if (!inService) {
                PolicyConfiguration policyConfiguration = factory.getPolicyConfiguration(contextId, false);
                PolicyConfiguration linkedPolicyConfiguration = factory.getPolicyConfiguration(linkedContextId, false);
                policyConfiguration.linkConfiguration(linkedPolicyConfiguration);
            }

            return lastInService;

        } catch (PolicyContextException | ClassNotFoundException pce) {
            throw new IllegalStateException(pce.toString());
        }
    }

    public void commitPolicy() {
        try {
            if (!factory.inService(contextId)) {

                // Note that it is presumed that the policyConfiguration exists, and that
                // it is populated with the desired policy statements.
                //
                // If this is not true, the call to commit will not result in the correct
                // policy statements being made available to the policy module.
                policyConfiguration.commit();
                logger.log(FINE, () -> "Jakarta Authorization: committed policy for context: " + contextId);
            }

            policy.refresh();
        } catch (PolicyContextException pce) {
            throw new IllegalStateException(pce);
        }
    }

    public static void commitPolicy(String contextId) {
        try {
            if (!PolicyConfigurationFactory.getPolicyConfigurationFactory().inService(contextId)) {

                // Note that it is presumed that the policyConfiguration exists, and that
                // it is populated with the desired policy statements.
                //
                // If this is not true, the call to commit will not result in the correct
                // policy statements being made available to the policy module.
                PolicyConfigurationFactory.getPolicyConfigurationFactory().getPolicyConfiguration(contextId, false).commit();
                logger.log(FINE, () -> "Jakarta Authorization: committed policy for context: " + contextId);
            }

            Policy.getPolicy().refresh();
        } catch (PolicyContextException | ClassNotFoundException pce) {
            throw new IllegalStateException(pce);
        }
    }

    public void refresh() {
        // Refresh policy if the context was in service
        try {
            if (factory.inService(contextId)) {
                policy.refresh();
            }
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

    public boolean checkWebUserDataPermission(String uri, String httpMethod, boolean requestIsSecure) {
        return checkPermission(
                new WebUserDataPermission(
                    uri,
                    httpMethod == null ? null : new String[] { httpMethod },
                    requestIsSecure ? "CONFIDENTIAL" : null));
    }

    public boolean checkWebUserDataPermission(String uri, String httpMethod, boolean requestIsSecure, Set<Principal> principals) {
        return checkPermission(
                new WebUserDataPermission(
                    uri,
                    httpMethod == null ? null : new String[] { httpMethod },
                    requestIsSecure ? "CONFIDENTIAL" : null),
                    principals);
    }

    public boolean checkPublicWebResourcePermission(HttpServletRequest request) {
        return checkPermission(new WebResourcePermission(getConstrainedURI(request), request.getMethod()));
    }

    public boolean checkWebResourcePermission(HttpServletRequest request) {
        try {
            Subject subject = (Subject) PolicyContext.getContext(SUBJECT);

            return checkWebResourcePermission(
                request,
                subject == null? null : subject.getPrincipals());
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean checkWebResourcePermission(HttpServletRequest request, Set<Principal> principals) {
        return checkPermission(
            new WebResourcePermission(
                getConstrainedURI(request),
                request.getMethod()),
                principals);
    }

    public boolean checkWebRoleRefPermission(String servletName, String role) {
        try {
            Subject subject = (Subject) PolicyContext.getContext(SUBJECT);

            return checkWebRoleRefPermission(
                servletName,
                role,
                subject == null? null : subject.getPrincipals());
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean checkWebRoleRefPermission(String servletName, String role, Set<Principal> principals) {
        return checkPermission(
                new WebRoleRefPermission(servletName, role),
                principals);
    }

    /**
     * Inform the policy module to take the named policy context out of service. The policy context is transitioned to the
     * deleted state.
     *
     * @param contextId the module id which serves to identify the corresponding policy context. The name shall not be
     * null.
     */
    public void deletePolicy() {
        try {
            boolean wasInService = factory.inService(contextId);

            // Find the PolicyConfig and delete it.
            factory.getPolicyConfiguration(contextId, false).delete();

            // Only do refresh policy if the deleted context was in service
            if (wasInService) {
                policy.refresh();
            }

        } catch (PolicyContextException pce) {
            throw new IllegalStateException(pce.toString());
        }
    }

    public static void deletePolicy(String contextId) {
        try {
            PolicyConfigurationFactory factory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

            boolean wasInService = factory.inService(contextId);

            // Find the PolicyConfig and delete it.
            factory.getPolicyConfiguration(contextId, false).delete();

            // Only do refresh policy if the deleted context was in service
            if (wasInService) {
                Policy.getPolicy().refresh();
            }

        } catch (PolicyContextException | ClassNotFoundException pce) {
            throw new IllegalStateException(pce.toString());
        }
    }


    boolean checkPermission(Permission permissionToBeChecked) {
        return policy.implies(emptyProtectionDomain, permissionToBeChecked);
    }

    boolean checkPermission(Permission permissionToBeChecked, Set<Principal> principals) {
        return policy.implies(newProtectionDomain(principals), permissionToBeChecked);
    }

    private static PolicyConfigurationFactory installFactory(Class<?> factoryClass) {
        System.setProperty(FACTORY, factoryClass.getName());

        return getFactory();
    }

    private static Policy installPolicy(Class<? extends Policy> policyClass) {
        try {
            Policy.setPolicy(policyClass.getConstructor().newInstance());

            return getPolicy();
        } catch (ReflectiveOperationException | IllegalArgumentException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static PolicyConfigurationFactory getFactory() {
        try {
            return PolicyConfigurationFactory.getPolicyConfigurationFactory();
        } catch (ClassNotFoundException | PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Policy getPolicy() {
        return Policy.getPolicy();
    }

    private ProtectionDomain newProtectionDomain(Set<Principal> principalSet) {
        return new ProtectionDomain(
                emptyCodeSource,
                null,
                null,
                principalSet == null ? null : (Principal[]) principalSet.toArray(new Principal[0]));
    }

    private String getConstrainedURI(HttpServletRequest request) {
        if (constrainedUriRequestAttribute != null) {
            String uri = (String) request.getAttribute(constrainedUriRequestAttribute);
            if (uri != null) {
                return uri;
            }
        }

        String relativeURI = getRequestRelativeURI(request);
        if (relativeURI.equals("/")) {
            return "";
        }

        return relativeURI.replaceAll(":", "%3A");
    }

    private String getRequestRelativeURI(HttpServletRequest request) {
        return request.getRequestURI().substring(request.getContextPath().length());
    }

    public static String getServletContextId(ServletContext context) {
        return context.getVirtualServerName() + " " + context.getContextPath();
    }

    public static void setThreadContextId(ServletContext context) {
        PolicyContext.setContextID(getServletContextId(context));
    }

    public static void setThreadContextId(String contextId) {
        PolicyContext.setContextID(contextId);
    }

}
