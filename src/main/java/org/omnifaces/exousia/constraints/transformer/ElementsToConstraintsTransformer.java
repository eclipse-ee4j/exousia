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
package org.omnifaces.exousia.constraints.transformer;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static javax.servlet.annotation.ServletSecurity.EmptyRoleSemantic.DENY;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.HttpMethodConstraintElement;
import javax.servlet.ServletSecurityElement;
import javax.servlet.annotation.HttpMethodConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.ServletSecurity.EmptyRoleSemantic;
import javax.servlet.annotation.ServletSecurity.TransportGuarantee;

import org.omnifaces.exousia.constraints.SecurityConstraint;
import org.omnifaces.exousia.constraints.WebResourceCollection;

/**
 * 
 * @author Arjan Tijms
 */
public class ElementsToConstraintsTransformer {

    public static List<SecurityConstraint> createConstraints(Set<String> urlPatterns, ServletSecurityElement servletSecurityElement) {
        if (urlPatterns.isEmpty()) {
            return emptyList();
        }

        List<SecurityConstraint> constraints = new ArrayList<>();
        Set<String> httpMethodOmissions = new HashSet<>();
        
        // Handle the constraints that hold for specific HTTP methods

        for (HttpMethodConstraintElement httpMethodConstraint : servletSecurityElement.getHttpMethodConstraints()) {
            constraints.add(createSecurityConstraint(
                urlPatterns, 
                httpMethodConstraint.getRolesAllowed(),
                httpMethodConstraint.getEmptyRoleSemantic(), 
                httpMethodConstraint.getTransportGuarantee(), 
                httpMethodConstraint.getMethodName(),
                emptySet()));

            // Methods handled by the httpMethodConstraint are not handled by special "all methods" constraint 
            httpMethodOmissions.add(httpMethodConstraint.getMethodName());
        }
        
        // Handle the special constraint that holds for all HTTP methods, accept those handled by the method
        // specific constraints
        
        constraints.add(createSecurityConstraint(
                urlPatterns, 
                servletSecurityElement.getRolesAllowed(),
                servletSecurityElement.getEmptyRoleSemantic(), 
                servletSecurityElement.getTransportGuarantee(), 
                null,
                httpMethodOmissions));
        
        return constraints;
    }
    
    public static List<SecurityConstraint> createConstraints(Set<String> urlPatterns, ServletSecurity servletSecurity) {
        if (urlPatterns.isEmpty()) {
            return emptyList();
        }

        List<SecurityConstraint> constraints = new ArrayList<>();
        Set<String> httpMethodOmissions = new HashSet<>();
        
        // Handle the constraints that hold for specific HTTP methods

        for (HttpMethodConstraint httpMethodConstraint : servletSecurity.httpMethodConstraints()) {
            constraints.add(createSecurityConstraint(
                urlPatterns, 
                httpMethodConstraint.rolesAllowed(),
                httpMethodConstraint.emptyRoleSemantic(), 
                httpMethodConstraint.transportGuarantee(), 
                httpMethodConstraint.value(),
                emptySet()));

            // Methods handled by the httpMethodConstraint are not handled by special "all methods" constraint 
            httpMethodOmissions.add(httpMethodConstraint.value());
        }
        
        // Handle the special constraint that holds for all HTTP methods, accept those handled by the method
        // specific constraints
        
        constraints.add(createSecurityConstraint(
                urlPatterns, 
                servletSecurity.value().rolesAllowed(),
                servletSecurity.value().value(), 
                servletSecurity.value().transportGuarantee(), 
                null,
                httpMethodOmissions));
        
        return constraints;
    }

    private static SecurityConstraint createSecurityConstraint(Set<String> urlPatterns, String[] rolesAllowed, EmptyRoleSemantic emptyRoleSemantic, TransportGuarantee transportGuarantee, String httpMethod, Set<String> httpMethodOmissions) {
        return new SecurityConstraint(asList(
            new WebResourceCollection(
                urlPatterns, createHttpMethods(httpMethod), httpMethodOmissions)), 
            createRolesAllowed(
                rolesAllowed, emptyRoleSemantic), 
            transportGuarantee);
    }
    
    private static Set<String> createRolesAllowed(String[] rolesAllowed, EmptyRoleSemantic emptyRoleSemantic) {
        if (rolesAllowed != null && rolesAllowed.length > 0) {
            if (emptyRoleSemantic == DENY) {
                throw new IllegalArgumentException("Cannot use DENY with non-empty rolesAllowed");
            }
            
            return new HashSet<>(asList(rolesAllowed));
        }
        
        if (emptyRoleSemantic == DENY) {
            return emptySet();
        }
        
        // Null means PERMIT
        return null;
    }
    
    private static Set<String> createHttpMethods(String httpMethod) {
        if (httpMethod == null) {
            return emptySet();
        }
        
        return new HashSet<>(asList(httpMethod));
    }

}
