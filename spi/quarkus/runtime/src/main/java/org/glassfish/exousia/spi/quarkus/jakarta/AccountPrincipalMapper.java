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

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import io.undertow.security.idm.Account;
import jakarta.security.jacc.PrincipalMapper;
import javax.security.auth.Subject;

/**
 * Maps the Subject of an Undertow {@link Account} to the caller principal and the application roles.
 *
 * <p>
 * The Subject holds the account's principal, and a {@link RolesPrincipal} with the account's roles. In Quarkus the
 * account's roles are those of the SecurityIdentity, so for instance the groups set by a Jakarta Authentication
 * ServerAuthModule, or the roles of a Quarkus identity provider.
 */
public class AccountPrincipalMapper implements PrincipalMapper {

    /**
     * @param account the authenticated account, or null if the caller is not authenticated
     * @return the Subject representing the account, which is empty if the caller is not authenticated
     */
    public static Subject toSubject(Account account) {
        return account != null ? toSubject(account.getPrincipal(), account.getRoles()) : new Subject();
    }

    /**
     * @param principal the caller principal, or null if the caller is not authenticated
     * @param roles the caller's roles
     * @return the Subject representing the caller, which is empty if the caller is not authenticated
     */
    public static Subject toSubject(Principal principal, Set<String> roles) {
        Subject subject = new Subject();

        if (principal != null) {
            subject.getPrincipals().add(principal);
            subject.getPrincipals().add(new RolesPrincipal(principal.getName(), Set.copyOf(roles)));
        }

        return subject;
    }

    @Override
    public Principal getCallerPrincipal(Subject subject) {
        for (Principal principal : subject.getPrincipals()) {
            if (!(principal instanceof RolesPrincipal)) {
                return principal;
            }
        }

        return null;
    }

    @Override
    public Set<String> getMappedRoles(Subject subject) {
        Set<String> roles = new HashSet<>();
        for (RolesPrincipal rolesPrincipal : subject.getPrincipals(RolesPrincipal.class)) {
            roles.addAll(rolesPrincipal.roles());
        }

        return roles;
    }

    /**
     * Carries the roles of an account in a Subject.
     *
     * @param name the name of the account's principal
     * @param roles the account's roles
     */
    public record RolesPrincipal(String name, Set<String> roles) implements Principal {

        @Override
        public String getName() {
            return name;
        }
    }
}
