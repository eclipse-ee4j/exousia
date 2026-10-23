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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.net.URL;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(ArquillianExtension.class)
class ConstraintsTest {

    @ArquillianResource
    private URL base;

    @Deployment(testable = false)
    static WebArchive deployment() {
        return ShrinkWrap.create(WebArchive.class, "constraints.war")
                         .addClass(InfoServlet.class)
                         .addAsWebInfResource(new File("src/main/webapp/WEB-INF/web.xml"));
    }

    @Test
    void publicAnonymous() throws Exception {
        var response = Http.get(base, "public", null, null);
        assertEquals(200, response.statusCode());
        assertEquals("user=null architect=false user=false", response.body());
    }

    @Test
    void protectedAnonymousIsChallenged() throws Exception {
        assertEquals(401, Http.get(base, "protected", null, null).statusCode());
    }

    @Test
    void protectedInRole() throws Exception {
        var response = Http.get(base, "protected", "reza", "secret1");
        assertEquals(200, response.statusCode());
        assertEquals("user=reza architect=true user=false", response.body());
    }

    @Test
    void protectedNotInRole() throws Exception {
        assertEquals(403, Http.get(base, "protected", "bob", "secret2").statusCode());
    }

    @Test
    void excluded() throws Exception {
        assertEquals(403, Http.get(base, "excluded", "reza", "secret1").statusCode());
    }

    @Test
    void publicAuthenticatedHasRoles() throws Exception {
        assertEquals("user=bob architect=false user=true", Http.get(base, "public", "bob", "secret2").body());
    }
}
