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

import java.util.List;
import java.util.Set;

import org.glassfish.exousia.constraints.SecurityConstraint;
import org.glassfish.exousia.constraints.WebResourceCollection;
import org.glassfish.exousia.constraints.transformer.ConstraintsToPermissionsTransformer;
import org.glassfish.exousia.permissions.JakartaPermissions;
import org.junit.Test;

import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.CONFIDENTIAL;
import static java.util.Arrays.asList;

public class TransformTest {


    @Test
    public void transformTestNoMethods() {
        JakartaPermissions permissions =
            ConstraintsToPermissionsTransformer.createResourceAndDataPermissions(
                Set.of("foo", "bar"),
                false,
                List.of(
                    new SecurityConstraint(
                        asList(
                            new WebResourceCollection("/*")),
                        null,
                        CONFIDENTIAL)));

        System.out.println("Excluded\n" + permissions.getExcluded());
        System.out.println("Unchecked\n" + permissions.getUnchecked());
        System.out.println("Per role\n" + permissions.getPerRole());
    }

    @Test
    public void transformTestMethods() {
        JakartaPermissions permissions =
            ConstraintsToPermissionsTransformer.createResourceAndDataPermissions(
                Set.of("foo", "bar"),
                false,
                List.of(
                    new SecurityConstraint(
                        asList(
                            new WebResourceCollection(
                                Set.of(
                                    "/*"),
                                Set.of(
                                    "GET",
                                    "HEAD",
                                    "POST",
                                    "PUT",
                                    "DELETE",
                                    "CONNECT",
                                    "OPTIONS",
                                    "TRACE",
                                    "PATCH"))),
                        null,
                        CONFIDENTIAL)));

        System.out.println("Excluded\n" + permissions.getExcluded());
        System.out.println("Unchecked\n" + permissions.getUnchecked());
        System.out.println("Per role\n" + permissions.getPerRole());
    }

    @Test
    public void transformTestMethodsDenyUncoveredHttpMethods() {
        JakartaPermissions permissions =
            ConstraintsToPermissionsTransformer.createResourceAndDataPermissions(
                Set.of("foo", "bar"),
                true, // isDenyUncoveredHttpMethods
                List.of(
                    new SecurityConstraint(
                        asList(
                            new WebResourceCollection(
                                Set.of(
                                    "/*"),
                                Set.of(
                                    "GET",
                                    "HEAD",
                                    "POST",
                                    "PUT",
                                    "DELETE",
                                    "CONNECT",
                                    "OPTIONS",
                                    "TRACE",
                                    "PATCH"))),
                        null,
                        CONFIDENTIAL)));

        System.out.println("Excluded\n" + permissions.getExcluded());
        System.out.println("Unchecked\n" + permissions.getUnchecked());
        System.out.println("Per role\n" + permissions.getPerRole());
    }


}
