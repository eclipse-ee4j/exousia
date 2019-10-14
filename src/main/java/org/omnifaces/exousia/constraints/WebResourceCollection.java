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
package org.omnifaces.exousia.constraints;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class WebResourceCollection {
    
    private final Set<String> urlPatterns;
    private final Set<String> httpMethods;
    private final Set<String> httpMethodOmissions;
    
    public WebResourceCollection(String... urlPatterns) {
        this(asList(urlPatterns));
    }
    
    public WebResourceCollection(List<String> urlPatterns) {
        this(new HashSet<>(urlPatterns), emptySet(), emptySet());
    }
    
    public WebResourceCollection(List<String> urlPatterns, List<String> httpMethods, List<String> httpMethodOmissions) {
        this(new HashSet<>(urlPatterns), new HashSet<>(httpMethods), new HashSet<>(httpMethodOmissions));
    }
    
    public WebResourceCollection(Set<String> urlPatterns, Set<String> httpMethods) {
        this(urlPatterns, httpMethods, emptySet());
    }
    
    public WebResourceCollection(Set<String> urlPatterns, Set<String> httpMethods, Set<String> httpMethodOmissions) {
        this.urlPatterns = unmodifiableSet(urlPatterns);
        this.httpMethods = unmodifiableSet(httpMethods);
        this.httpMethodOmissions = unmodifiableSet(httpMethodOmissions);
    }

    public Set<String> getUrlPatterns() {
        return urlPatterns;
    }

    public Set<String> getHttpMethods() {
        return httpMethods;
    }

    public Set<String> getHttpMethodOmissions() {
        return httpMethodOmissions;
    }

   
}