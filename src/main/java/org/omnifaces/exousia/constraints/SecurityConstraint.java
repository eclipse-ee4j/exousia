/*
 * Copyright (c) 2019, 2020 OmniFaces. All rights reserved.
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
package org.omnifaces.exousia.constraints;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableSet;
import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.NONE;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import jakarta.servlet.annotation.ServletSecurity.TransportGuarantee;

public class SecurityConstraint {

    private final List<WebResourceCollection> webResourceCollections;
    private final Set<String> rolesAllowed;
    private final TransportGuarantee transportGuarantee;

    public SecurityConstraint(String urlPattern, String... rolesAllowed) {
        this(new WebResourceCollection(urlPattern), rolesAllowed);
    }

    public SecurityConstraint(WebResourceCollection webResourceCollection, String... rolesAllowed) {
        this(asList(webResourceCollection), asList(rolesAllowed));
    }

    public SecurityConstraint(List<WebResourceCollection> webResourceCollections, String... rolesAllowed) {
        this(webResourceCollections, asList(rolesAllowed));
    }

    public SecurityConstraint(List<WebResourceCollection> webResourceCollections, List<String> rolesAllowed) {
        this(webResourceCollections, new HashSet<>(rolesAllowed));
    }

    public SecurityConstraint(List<WebResourceCollection> webResourceCollections, Set<String> rolesAllowed) {
        this(webResourceCollections, rolesAllowed, NONE);
    }

    public SecurityConstraint(List<WebResourceCollection> webResourceCollections, Set<String> rolesAllowed, TransportGuarantee transportGuarantee) {
        this.webResourceCollections = unmodifiableList(webResourceCollections);
        this.rolesAllowed = unmodifiableSet(rolesAllowed);
        this.transportGuarantee = transportGuarantee;
    }

    public List<WebResourceCollection> getWebResourceCollections() {
        return webResourceCollections;
    }

    public TransportGuarantee getTransportGuarantee() {
        return transportGuarantee;
    }

    public Set<String> getRolesAllowed() {
        return rolesAllowed;
    }

}
