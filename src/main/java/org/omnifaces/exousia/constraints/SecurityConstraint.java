package org.omnifaces.exousia.constraints;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableSet;
import static javax.servlet.annotation.ServletSecurity.TransportGuarantee.NONE;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.annotation.ServletSecurity.TransportGuarantee;

public class SecurityConstraint {
    
    private final List<WebResourceCollection> webResourceCollections;
    private final Set<String> rolesAllowed;
    private final TransportGuarantee transportGuarantee;
    
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
