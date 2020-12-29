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
package org.omnifaces.exousia.spi.integration.tomcat;

import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.CONFIDENTIAL;
import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.NONE;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyMap;
import static org.apache.catalina.authenticator.Constants.REQ_JASPIC_SUBJECT_NOTE;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.security.auth.Subject;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.omnifaces.exousia.AuthorizationService;
import org.omnifaces.exousia.constraints.WebResourceCollection;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequestEvent;
import jakarta.servlet.ServletRequestListener;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;

/**
 *
 * @author Arjan Tijms
 *
 */
public class TomcatAuthorizationFilter extends HttpFilter implements ServletRequestListener {

    private static final long serialVersionUID = 1L;

    public static ThreadLocal<HttpServletRequest> localServletRequest = new ThreadLocal<>();

    @Override
    public void init() throws ServletException {
        ServletContext servletContext = getFilterConfig().getServletContext();

        StandardRoot root = (StandardRoot) servletContext.getAttribute("org.apache.catalina.resources");
        Context context = root.getContext();

        // Get all the security constraints from Tomcat
        SecurityConstraint[] constraints = context.findConstraints();
        List<String> declaredRoles = asList(context.findSecurityRoles());
        boolean isDenyUncoveredHttpMethods = root.getContext().getDenyUncoveredHttpMethods();

        AuthorizationService.setThreadContextId(servletContext);

        // Initialize the AuthorizationService, which is a front-end for Jakarta Authorization.
        // It specifically tells Jakarta Authorization how to get the current request, and the current subject
        AuthorizationService authorizationService = new AuthorizationService(
            servletContext,
            () -> localServletRequest.get(),
            () -> getSubject(localServletRequest.get()));

        // Copy all the security constraints that Tomcat has collected to the Jakarta Authorization
        // repository as well. That way Jakarta Authorization can work with the same data as Tomcat
        // internally does.
        authorizationService.addConstraintsToPolicy(
            convertTomcatConstraintsToExousia(constraints),
            new HashSet<>(declaredRoles), isDenyUncoveredHttpMethods, emptyMap());

    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        // Sets the initial request.
        // Note that we should actually have the request used before every filter and Servlet that will be executed.
        localServletRequest.set((HttpServletRequest) sre.getServletRequest());

        // Sets the context ID in the current thread. The context ID is a unique name for the current web application and
        // is used by Jakarta Authorization and Exousia.
        AuthorizationService.setThreadContextId(sre.getServletContext());
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
        localServletRequest.remove();
    }

    /**
     * Transforms the security constraints (web.xml, annotations, and programmatic) from the Tomcat types to Exousia types.
     *
     * @param tomcatConstraints
     * @return
     */
    private List<org.omnifaces.exousia.constraints.SecurityConstraint> convertTomcatConstraintsToExousia(org.apache.tomcat.util.descriptor.web.SecurityConstraint[] tomcatConstraints) {
        if (tomcatConstraints == null || tomcatConstraints.length == 0) {
            return null;
        }

        List<org.omnifaces.exousia.constraints.SecurityConstraint> exousiaConstraints = new ArrayList<>();

        for (SecurityConstraint tomcatConstraint : tomcatConstraints) {

            List<WebResourceCollection> exousiaWebResourceCollections = new ArrayList<>();
            for (SecurityCollection tomcatSecurityCollection : tomcatConstraint.findCollections()) {
                exousiaWebResourceCollections.add(new WebResourceCollection(
                        tomcatSecurityCollection.findPatterns(),
                        tomcatSecurityCollection.findMethods(),
                        tomcatSecurityCollection.findOmittedMethods()));
            }

            exousiaConstraints.add(new org.omnifaces.exousia.constraints.SecurityConstraint(
                    exousiaWebResourceCollections,
                    new HashSet<>(asList(tomcatConstraint.findAuthRoles())),
                    "confidential".equalsIgnoreCase(tomcatConstraint.getUserConstraint())
                    ? CONFIDENTIAL : NONE));

        }

        return exousiaConstraints;
    }

    /**
     * Gets the authenticated Subject (if any) from the Tomcat specific location inside the HttpServletRequest instance.
     *
     * @param httpServletRequest the instance to get the Subject from
     * @return the Subject if the caller authenticated via Jakarta Authentication (JASPIC), otherwise null
     */
    private static Subject getSubject(HttpServletRequest httpServletRequest) {
        return (Subject) getRequest(httpServletRequest).getNote(REQ_JASPIC_SUBJECT_NOTE);
    }

    private static Request getRequest(HttpServletRequest servletRequest) {
        return getRequest((RequestFacade) servletRequest);
    }

    private static Request getRequest(RequestFacade facade) {
        try {
            Field requestField = RequestFacade.class.getDeclaredField("request");
            requestField.setAccessible(true);

            return (Request) requestField.get(facade);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }

    }

}
