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