/*
 * Copyright (c) 2023, 2024 Contributors to the Eclipse Foundation.
 * Copyright (c) 2019, 2021 OmniFaces. All rights reserved.
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

import static jakarta.security.jacc.PolicyContext.HTTP_SERVLET_REQUEST;
import static jakarta.security.jacc.PolicyContext.PRINCIPAL_MAPPER;
import static jakarta.security.jacc.PolicyContext.SUBJECT;
import static java.util.Collections.emptySet;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.SEVERE;
import static org.glassfish.exousia.constraints.transformer.ConstraintsToPermissionsTransformer.createResourceAndDataPermissions;
import static org.glassfish.exousia.permissions.RolesToPermissionsTransformer.createWebRoleRefPermission;

import jakarta.security.jacc.EJBMethodPermission;
import jakarta.security.jacc.EJBRoleRefPermission;
import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PolicyFactory;
import jakarta.security.jacc.PrincipalMapper;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;
import jakarta.security.jacc.WebUserDataPermission;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.security.Permission;
import java.security.Permissions;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import org.glassfish.exousia.constraints.SecurityConstraint;
import org.glassfish.exousia.mapping.DefaultPrincipalMapper;
import org.glassfish.exousia.mapping.SecurityRoleRef;
import org.glassfish.exousia.modules.def.DefaultPolicy;
import org.glassfish.exousia.modules.def.DefaultPolicyConfigurationFactory;
import org.glassfish.exousia.permissions.JakartaPermissions;

/**
 *
 * @author Arjan Tijms
 */
public class AuthorizationService {

    static final Logger logger = Logger.getLogger(AuthorizationService.class.getName());

    public static final String ENTERPRISE_BEAN = "jakarta.ejb.EnterpriseBean";
    public static final String ENTERPRISE_BEAN_ARGUMENTS = "jakarta.ejb.arguments";

    private final String contextId;

    /**
     * The authorization policy. This is the class that makes the actual decision for a permission
     * request.
     */
    private final Policy policy;
    private final PolicyFactory policyFactory;
    private final PolicyConfigurationFactory factory;
    private final PolicyConfiguration policyConfiguration;
    private final Map<String, jakarta.security.jacc.PrincipalMapper> principalMapper = new ConcurrentHashMap<>();

    private String constrainedUriRequestAttribute;

    public AuthorizationService(
            ServletContext servletContext,
            Supplier<Subject> subjectSupplier) {
        this(
            DefaultPolicyConfigurationFactory.class,
            DefaultPolicy.class,
            getServletContextId(servletContext), subjectSupplier);
    }

    public AuthorizationService(
            String contextId,
            Supplier<Subject> subjectSupplier) {
        this(
            DefaultPolicyConfigurationFactory.class,
            DefaultPolicy.class,
            contextId, subjectSupplier);
    }

    public AuthorizationService(
            Class<?> factoryClass, Class<? extends Policy> policyClass, String contextId,
            Supplier<Subject> subjectSupplier) {
        this(factoryClass, policyClass, contextId, subjectSupplier, null);
    }

    public AuthorizationService(
            Class<?> factoryClass, Class<? extends Policy> policyClass, String contextId,
            Supplier<Subject> subjectSupplier, Supplier<PrincipalMapper> principalMapperSupplier) {

        this(
            installFactory(factoryClass), installPolicy(policyClass), contextId,
            subjectSupplier, principalMapperSupplier);
    }

    public AuthorizationService(
        String contextId,
        Supplier<Subject> subjectSupplier, Supplier<PrincipalMapper> principalMapperSupplier) {

        this(
            getConfigurationFactory(), null, contextId,
            subjectSupplier, principalMapperSupplier);
    }

    public AuthorizationService(
        PolicyConfigurationFactory factory, Policy policy, String contextId,
        Supplier<Subject> subjectSupplier, Supplier<PrincipalMapper> principalMapperSupplier) {
        try {
            this.factory = factory;
            this.policyConfiguration = factory.getPolicyConfiguration(contextId, false);
            this.policy = policy;
            this.contextId = contextId;
            this.policyFactory = PolicyFactory.getPolicyFactory();

            // Sets the context Id (aka application Id), which may be used by authorization modules to get the right
            // authorization config
            PolicyContext.setContextID(contextId);

            PolicyContext.registerHandler(
                SUBJECT,
                new DefaultPolicyContextHandler(contextId, SUBJECT, subjectSupplier),
                true);

            PolicyContext.registerHandler(
                PRINCIPAL_MAPPER,
                new DefaultPolicyContextHandler(contextId, PRINCIPAL_MAPPER, () ->
                    getOrCreatePrincipalMapper(
                        contextId,
                        principalMapperSupplier != null? principalMapperSupplier : () -> getDefaultRoleMapper(contextId))),
                true);

        } catch (PolicyContextException | IllegalArgumentException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public void setRequestSupplier(String contextId, Supplier<HttpServletRequest> requestSupplier) {
        try {
            PolicyContext.registerHandler(
                HTTP_SERVLET_REQUEST,
                new DefaultPolicyContextHandler(contextId, HTTP_SERVLET_REQUEST, requestSupplier),
                true);
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public void setSubjectSupplier(String contextId, Supplier<Subject> subjectSupplier) {
        try {
            PolicyContext.registerHandler(
                SUBJECT,
                new DefaultPolicyContextHandler(contextId, SUBJECT, subjectSupplier),
                true);
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public void setEnterpriseBeanSupplier(String contextId, Supplier<Object> beanSupplier) {
        try {
            PolicyContext.registerHandler(
                ENTERPRISE_BEAN,
                new DefaultPolicyContextHandler(contextId, ENTERPRISE_BEAN, beanSupplier),
                true);
        } catch (PolicyContextException e) {
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
            JakartaPermissions jakartaResourceDataPermissions = createResourceAndDataPermissions(declaredRoles, isDenyUncoveredHttpMethods, securityConstraints);
            addPermissionsToPolicy(jakartaResourceDataPermissions);

            JakartaPermissions jakartaRoleRefPermissions = createWebRoleRefPermission(declaredRoles, servletRoleMappings);
            addPermissionsToPolicy(jakartaRoleRefPermissions);

        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public void addPermissionsToPolicy(JakartaPermissions jakartaPermissions) {
        try {
            // Add the translated/generated excluded permissions
            policyConfiguration.addToExcludedPolicy(jakartaPermissions.getExcluded());

            // Add the translated/generated unchecked permissions
            policyConfiguration.addToUncheckedPolicy(jakartaPermissions.getUnchecked());

            // Add the translated/generated per role resource permissions
            for (Entry<String, Permissions> roleEntry : jakartaPermissions.getPerRole().entrySet()) {
                policyConfiguration.addToRole(roleEntry.getKey(), roleEntry.getValue());
            }

        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public void removeStatementsFromPolicy(Set<String> declaredRoles) {
        try {
            boolean inService = factory.inService(contextId);

            // Open policy configuration
            PolicyConfiguration policyConfiguration = factory.getPolicyConfiguration(contextId, false);

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
                // TODO: is this needed? refresh seems to do no nothing
                getPolicy().refresh();
            }
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * This method obtains the policy configuration object corresponding to the name, and links it, for roleMapping purposes
     * to another. If the policy configuration is already InService when this method is called, this method does nothing.
     *
     * @param linkedContextId - the module id of the module being linked to this context. This value may be null, in which
     * case, no link is done, but the inService state of the named PC is returned.
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

            getPolicy().refresh();
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

            PolicyFactory.getPolicyFactory().getPolicy().refresh();
        } catch (PolicyContextException | ClassNotFoundException pce) {
            throw new IllegalStateException(pce);
        }
    }

    public void refresh() {
        // Refresh policy if the context was in service
        try {
            if (factory.inService(contextId)) {
                getPolicy().refresh();
            }
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public void destroy() {
        DefaultPolicyContextHandler.removeAllForContextId(contextId);
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
            Subject subject = PolicyContext.getContext(SUBJECT);

            return checkWebResourcePermission(
                request,
                subject);
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean checkWebResourcePermission(HttpServletRequest request, Subject subject) {
        return checkPermission(
            new WebResourcePermission(
                getConstrainedURI(request),
                request.getMethod()),
                subject);
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
            Subject subject = PolicyContext.getContext(SUBJECT);

            return checkWebRoleRefPermission(
                servletName,
                role,
                subject);
        } catch (PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean checkWebRoleRefPermission(String servletName, String role, Subject subject) {
        return checkPermission(
                new WebRoleRefPermission(servletName, role),
                subject);
    }

    public boolean checkWebRoleRefPermission(String servletName, String role, Set<Principal> principals) {
        return checkPermission(
                new WebRoleRefPermission(servletName, role),
                principals);
    }

    public boolean checkBeanRoleRefPermission(String beanName, String role, Set<Principal> principals) {
        EJBRoleRefPermission ejbRoleRefPermission = new EJBRoleRefPermission(beanName, role);

        boolean isCallerInRole = checkPermissionScoped(ejbRoleRefPermission, principals);

        logger.fine(() ->
            "Authorization: checkBeanRoleRefPermission Result: " + isCallerInRole +
            " EJBRoleRefPermission (Name) = " + ejbRoleRefPermission.getName() +
            " (Action) = " + ejbRoleRefPermission.getActions());

        return isCallerInRole;
    }

    public boolean checkBeanMethodPermission(String beanName, String methodInterface, Method method, Set<Principal> principals) {
        EJBMethodPermission methodPermission = new EJBMethodPermission(beanName, methodInterface, method);

        boolean authorized = checkPermissionScoped(methodPermission, principals);

        logger.fine(() ->
            "Authorization: Access Control Decision Result: " + authorized +
            " EJBMethodPermission (Name) = " + methodPermission.getName() +
            " (Action) = " + methodPermission.getActions());

       return authorized;
    }

    public Object invokeBeanMethod(Object bean, Method beanClassMethod, Object[] methodParameters) throws Throwable {
        return runInScope(() -> beanClassMethod.invoke(bean, methodParameters));
    }


    /**
     * Inform the policy module to take the named policy context out of service. The policy context is transitioned to the
     * deleted state.
     *
     */
    public void deletePolicy() {
        try {
            boolean wasInService = factory.inService(contextId);

            // Find the PolicyConfig and delete it.
            factory.getPolicyConfiguration(contextId, false).delete();

            // Only do refresh policy if the deleted context was in service
            if (wasInService) {
                getPolicy().refresh();
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
                PolicyFactory.getPolicyFactory().getPolicy().refresh();
            }

        } catch (PolicyContextException | ClassNotFoundException pce) {
            throw new IllegalStateException(pce.toString());
        }
    }


    boolean checkPermission(Permission permissionToBeChecked) {
        logger.log(FINEST, "checkPermission(permissionToBeChecked={0})", permissionToBeChecked);
        return getPolicy().implies(permissionToBeChecked);
    }

    boolean checkPermission(Permission permissionToBeChecked, Subject subject) {
        logger.log(FINEST, "checkPermission(permissionToBeChecked={0}, subject={1})",
            new Object[] {permissionToBeChecked, subject});
        return getPolicy().implies(permissionToBeChecked, subject != null? subject : new Subject());
    }

    boolean checkPermission(Permission permissionToBeChecked, Set<Principal> principals) {
        logger.log(FINEST, "checkPermission(permissionToBeChecked={0}, principals={1})",
            new Object[] {permissionToBeChecked, principals});
        return getPolicy().implies(permissionToBeChecked, principals != null? principals : emptySet());
    }

    boolean checkPermissionScoped(Permission permissionToBeChecked, Set<Principal> principals) {
        logger.log(FINEST, "checkPermissionScoped(permissionToBeChecked={0}, principals={1})",
            new Object[] {permissionToBeChecked, principals});
        String oldContextId = null;
        try {
            oldContextId = setThreadContextId(contextId);

            return getPolicy().implies(permissionToBeChecked, principals);
        } catch (Throwable t) {
            logger.log(SEVERE, "jacc_is_caller_in_role_exception", t);
        } finally {
            try {
                setPolicyContextChecked(oldContextId, contextId);
            } catch (Throwable ex) {
                logger.log(SEVERE, "jacc_policy_context_exception", ex);
            }
        }

        return false;
    }

    public Object runInScope(ThrowableSupplier<Object> supplier) throws Throwable {
        String oldContextId = setThreadContextId(contextId);
        try {
            return supplier.get();
        } finally {
            setPolicyContextChecked(oldContextId, contextId);
        }
    }

    private static PolicyConfigurationFactory installFactory(Class<?> factoryClass) {
        System.setProperty(PolicyConfigurationFactory.FACTORY_NAME, factoryClass.getName());

        return getConfigurationFactory();
    }

    private static Policy installPolicy(Class<? extends Policy> policyClass) {
        try {
            PolicyFactory.getPolicyFactory().setPolicy(policyClass.getConstructor().newInstance());

            return PolicyFactory.getPolicyFactory().getPolicy();
        } catch (ReflectiveOperationException | IllegalArgumentException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static PolicyConfigurationFactory getConfigurationFactory() {
        try {
            return PolicyConfigurationFactory.getPolicyConfigurationFactory();
        } catch (ClassNotFoundException | PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    private Policy getPolicy() {
        if (policy != null) {
            return policy;
        }

        // (or obtain once and cache?)
        return policyFactory.getPolicy(contextId);
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

    private PrincipalMapper getOrCreatePrincipalMapper(String contextId, Supplier<PrincipalMapper> principalMapperSupplier) {
        return principalMapper.computeIfAbsent(contextId, e -> principalMapperSupplier.get());
    }

    private PrincipalMapper getDefaultRoleMapper(String contextId) {
        return new DefaultPrincipalMapper(
            contextId,
            getAllDeclaredRoles());
    }

    private static Collection<String> getAllDeclaredRoles() {
        return getConfigurationFactory()
                .getPolicyConfiguration()
                .getPerRolePermissions()
                .keySet();
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

    public static String setThreadContextId(String contextId) {
        String oldContextId = PolicyContext.getContextID();

        setPolicyContextChecked(contextId, oldContextId);

        return oldContextId;
    }

    private static void setPolicyContextChecked(String newContextId, String oldContextId) {
        if (newContextId != null && (oldContextId == null || !oldContextId.equals(newContextId))) {

            logger.fine(() -> "Authorization: Changing Policy Context ID: oldContextId = " + oldContextId + " newContextId = " + newContextId);

            try {
                PolicyContext.setContextID(newContextId);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    @FunctionalInterface
    public interface ThrowableSupplier<T> {
        T get() throws Throwable;
    }

}
