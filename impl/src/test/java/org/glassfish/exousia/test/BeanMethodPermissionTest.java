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

package org.glassfish.exousia.test;

import jakarta.security.jacc.EJBMethodPermission;
import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyFactory;
import jakarta.security.jacc.PrincipalMapper;

import java.lang.reflect.Method;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;

import org.glassfish.exousia.AuthorizationService;
import org.glassfish.exousia.modules.def.DefaultPolicy;
import org.glassfish.exousia.modules.def.DefaultPolicyConfigurationFactory;
import org.glassfish.exousia.modules.def.DefaultPolicyFactory;
import org.glassfish.exousia.permissions.JakartaPermissions;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Bean method checks: an unchecked, an excluded and a role-protected method, asked by an anonymous caller and by one
 * in the role. DefaultPolicy answers implies(Permission, Set) without building a Subject for the first two, and
 * AuthorizationService keeps each method's permission; both must give the answers the plain default gives.
 */
public class BeanMethodPermissionTest {

    public interface Greeter {
        String open();
        String closed();
        String admin();
        String admin(int level);
    }

    private static final String BEAN = "GreeterBean";
    private static final String CONTEXT = "exousia-bean-method-test";
    private static final Principal ALICE = new NamedPrincipal("alice");

    private static AuthorizationService service;

    @BeforeClass
    public static void createPolicy() throws Exception {
        // What a container sets before it starts: the factories to use.
        System.setProperty(PolicyConfigurationFactory.FACTORY_NAME, DefaultPolicyConfigurationFactory.class.getName());
        System.setProperty(PolicyFactory.FACTORY_NAME, DefaultPolicyFactory.class.getName());

        PrincipalMapper mapper = new PrincipalMapper() {
            @Override
            public Principal getCallerPrincipal(Subject subject) {
                return subject.getPrincipals().stream().findFirst().orElse(null);
            }

            @Override
            public Set<String> getMappedRoles(Subject subject) {
                return subject.getPrincipals().contains(ALICE) ? Set.of("admin") : Set.of();
            }
        };
        service = new AuthorizationService(DefaultPolicyConfigurationFactory.class, DefaultPolicy.class, CONTEXT,
            () -> null, () -> mapper);

        JakartaPermissions permissions = new JakartaPermissions();
        permissions.getUnchecked().add(new EJBMethodPermission(BEAN, "Remote", method("open")));
        permissions.getExcluded().add(new EJBMethodPermission(BEAN, "Remote", method("closed")));
        Permissions admin = new Permissions();
        admin.add(new EJBMethodPermission(BEAN, "Remote", method("admin")));
        permissions.getPerRole().put("admin", admin);
        service.addPermissionsToPolicy(permissions);
        service.commitPolicy();
    }

    @Test
    public void bean_method_checks_give_the_expected_answers() throws Exception {
        assertTrue(check("open", Set.of()));
        assertTrue(check("open", Set.of(ALICE)));
        assertFalse(check("closed", Set.of()));
        assertFalse(check("closed", Set.of(ALICE)));
        assertFalse(check("admin", Set.of()));
        assertTrue(check("admin", Set.of(ALICE)));
    }

    @Test
    public void a_kept_permission_answers_as_a_new_one() throws Exception {
        for (int i = 0; i < 3; i++) {
            assertTrue(check("open", Set.of()));
            assertTrue(check("admin", Set.of(ALICE)));
            assertFalse(check("admin", Set.of()));
        }
        // An overload is a different method, with its own permission.
        assertFalse(service.checkBeanMethodPermission(BEAN, "Remote", Greeter.class.getMethod("admin", int.class),
            Set.of(ALICE)));
        // So is another interface.
        assertFalse(service.checkBeanMethodPermission(BEAN, "Local", method("admin"), Set.of(ALICE)));
    }

    @Test
    public void default_policy_answers_as_the_default_implies() throws Exception {
        Policy policy = PolicyFactory.getPolicyFactory().getPolicy(CONTEXT);
        Policy reference = new Policy() {
            @Override
            public boolean isExcluded(Permission permission) {
                return policy.isExcluded(permission);
            }

            @Override
            public boolean isUnchecked(Permission permission) {
                return policy.isUnchecked(permission);
            }

            @Override
            public boolean impliesByRole(Permission permission, Subject subject) {
                return policy.impliesByRole(permission, subject);
            }

            @Override
            public PermissionCollection getPermissionCollection(Subject subject) {
                return policy.getPermissionCollection(subject);
            }
        };
        for (String name : new String[] {"open", "closed", "admin"}) {
            for (Set<Principal> principals : java.util.List.<Set<Principal>>of(Set.of(), Set.of(ALICE), Set.of(new NamedPrincipal("bob")))) {
                Permission permission = new EJBMethodPermission(BEAN, "Remote", method(name));
                assertEquals(name + " " + principals, reference.implies(permission, principals),
                    policy.implies(permission, principals));
            }
        }
    }

    private static boolean check(String name, Set<Principal> principals) throws Exception {
        return service.checkBeanMethodPermission(BEAN, "Remote", method(name), principals);
    }

    private static Method method(String name) throws Exception {
        return Greeter.class.getMethod(name);
    }

    private static final class NamedPrincipal implements Principal {
        private final String name;

        NamedPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof NamedPrincipal && ((NamedPrincipal) o).name.equals(name);
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }
    }
}
