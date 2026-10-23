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
package org.glassfish.exousia.spi.quarkus.test;

import java.security.Permission;
import java.security.PermissionCollection;

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyFactory;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import javax.security.auth.Subject;

/** A custom policy that, unlike the constraints, doesn't grant /public to anonymous callers */
public class DenyAnonymousPublicPolicy implements Policy {

    private final Policy delegate;

    public DenyAnonymousPublicPolicy(Policy delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean implies(Permission permission, Subject subject) {
        if (isPublic(permission) && (subject == null || subject.getPrincipals().isEmpty())) {
            return false;
        }
        return delegate.implies(permission, subject);
    }

    @Override
    public boolean implies(Permission permission) {
        return !isPublic(permission) && delegate.implies(permission);
    }

    @Override
    public boolean isUnchecked(Permission permission) {
        return !isPublic(permission) && delegate.isUnchecked(permission);
    }

    @Override
    public PermissionCollection getPermissionCollection(Subject subject) {
        return delegate.getPermissionCollection(subject);
    }

    private static boolean isPublic(Permission permission) {
        return permission instanceof WebResourcePermission && permission.getName().equals("/public");
    }

    @WebListener
    public static class Installer implements ServletContextListener {
        @Override
        public void contextInitialized(ServletContextEvent sce) {
            PolicyFactory policyFactory = PolicyFactory.getPolicyFactory();
            policyFactory.setPolicy(new DenyAnonymousPublicPolicy(policyFactory.getPolicy()));
        }
    }
}
