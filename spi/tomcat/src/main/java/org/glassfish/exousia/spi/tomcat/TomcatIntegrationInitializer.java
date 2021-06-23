/*
 * Copyright (c) 2020 OmniFaces. All rights reserved.
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
package org.glassfish.exousia.spi.tomcat;

import java.util.Set;

import jakarta.servlet.ServletContainerInitializer;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;

/**
* This initializer installs a container specific integration between Exousia
* and Tomcat.
*
* @author Arjan Tijms
*
*/
public class TomcatIntegrationInitializer implements ServletContainerInitializer {

    @Override
    public void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException {
        if (isTomcat()) {
            ctx.addFilter(TomcatAuthorizationFilter.class.getCanonicalName(), TomcatAuthorizationFilter.class);
            ctx.addListener(TomcatAuthorizationFilter.class);
        }
    }

    private boolean isTomcat() {
        try {
            Class.forName("org.apache.tomcat.util.descriptor.web.SecurityConstraint");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

}
