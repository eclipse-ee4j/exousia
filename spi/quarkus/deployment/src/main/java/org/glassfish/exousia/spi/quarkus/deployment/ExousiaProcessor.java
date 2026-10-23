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
package org.glassfish.exousia.spi.quarkus.deployment;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.glassfish.exousia.spi.quarkus.vertx.ExousiaServletHttpSecurityPolicy;
import org.glassfish.exousia.spi.quarkus.undertow.ExousiaServletExtension;
import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;
import org.jboss.metadata.javaee.spec.SecurityRoleMetaData;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.ExcludedTypeBuildItem;
import io.quarkus.bootstrap.classloading.QuarkusClassLoader;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.IndexDependencyBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBundleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.undertow.deployment.ServletExtensionBuildItem;
import io.quarkus.undertow.deployment.WebMetadataBuildItem;
import io.quarkus.undertow.runtime.ServletHttpSecurityPolicy;

class ExousiaProcessor {

    private static final String FEATURE = "exousia";

    private static final DotName DECLARE_ROLES = DotName.createSimple("jakarta.annotation.security.DeclareRoles");

    /** The Epicyro (Jakarta Authentication) extension replaces Quarkus' Servlet security policy as well */
    private static final String EPICYRO_SERVLET_HTTP_SECURITY_POLICY = "org.glassfish.epicyro.quarkus.runtime.EpicyroServletHttpSecurityPolicy";

    /** Types Jakarta Authorization creates from a class name, given by a system property */
    private static final List<DotName> CREATED_BY_NAME = List.of(
            DotName.createSimple("jakarta.security.jacc.PolicyConfigurationFactory"),
            DotName.createSimple("jakarta.security.jacc.PolicyFactory"));

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    ServletExtensionBuildItem servletExtension(Optional<WebMetadataBuildItem> webMetadata, CombinedIndexBuildItem combinedIndex) {
        // Undertow deploys during static init, so the configuration is passed in at build time
        ExousiaServletExtension servletExtension = new ExousiaServletExtension();
        servletExtension.setSecurityRoles(getSecurityRoles(webMetadata, combinedIndex.getIndex()));

        return new ServletExtensionBuildItem(servletExtension);
    }

    /**
     * @return the roles declared by security-role in web.xml (and fragments) and by @DeclareRoles
     */
    private static Set<String> getSecurityRoles(Optional<WebMetadataBuildItem> webMetadata, IndexView index) {
        Set<String> securityRoles = new HashSet<>();

        if (webMetadata.isPresent() && webMetadata.get().getWebMetaData().getSecurityRoles() != null) {
            for (SecurityRoleMetaData securityRole : webMetadata.get().getWebMetaData().getSecurityRoles()) {
                securityRoles.add(securityRole.getRoleName());
            }
        }

        for (AnnotationInstance declareRoles : index.getAnnotations(DECLARE_ROLES)) {
            securityRoles.addAll(List.of(declareRoles.value().asStringArray()));
        }

        return securityRoles;
    }

    /**
     * Quarkus' Servlet security policy enforces the Servlet security constraints with Undertow's role checks, before the
     * request reaches Undertow. It's replaced by a policy that permits everything, so the Jakarta Authorization policy
     * decides in Undertow.
     *
     * <p>
     * Quarkus looks the policy up by its type, so there must be exactly one: when the Epicyro extension is present, its
     * replacement (which permits everything as well) is used.
     */
    @BuildStep
    void replaceServletHttpSecurityPolicy(BuildProducer<ExcludedTypeBuildItem> excludedTypes, BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
        if (QuarkusClassLoader.isClassPresentAtRuntime(EPICYRO_SERVLET_HTTP_SECURITY_POLICY)) {
            return;
        }

        excludedTypes.produce(new ExcludedTypeBuildItem(ServletHttpSecurityPolicy.class.getName()));
        additionalBeans.produce(AdditionalBeanBuildItem.unremovableOf(ExousiaServletHttpSecurityPolicy.class));
    }

    /** Index Exousia, so its own factories are found in {@link #createdByName}. */
    @BuildStep
    IndexDependencyBuildItem indexExousia() {
        return new IndexDependencyBuildItem("org.glassfish.exousia", "exousia");
    }

    /**
     * {@code PolicyConfigurationFactory} and {@code PolicyFactory} are created from the class name in a system property.
     * Register the constructors of all of them, from Exousia and the application, so that works in a native executable
     * as well.
     */
    @BuildStep
    ReflectiveClassBuildItem createdByName(CombinedIndexBuildItem combinedIndex) {
        IndexView index = combinedIndex.getIndex();
        List<String> classNames = new ArrayList<>();
        for (DotName type : CREATED_BY_NAME) {
            for (ClassInfo classInfo : index.getAllKnownSubclasses(type)) {
                if (!classInfo.isAbstract()) {
                    classNames.add(classInfo.name().toString());
                }
            }
        }

        return ReflectiveClassBuildItem.builder(classNames.toArray(String[]::new))
                .constructors()
                .reason(getClass().getName())
                .build();
    }

    /**
     * The locked module's policy configuration registers a role mapper when its class is initialized, chosen by a system
     * property and the {@code PolicyContext} handlers at that time. That's run-time state, so in a native executable the
     * class must be initialized at run time, not when the image is built.
     */
    @BuildStep
    RuntimeInitializedClassBuildItem initializeAtRunTime() {
        return new RuntimeInitializedClassBuildItem("org.glassfish.exousia.modules.locked.SimplePolicyConfiguration");
    }

    /**
     * A permission check adds the caller's principals to a {@code Subject}, whose null check gets its message from the
     * JDK's security resource bundle, even when there's no null. A native executable has that bundle only when it's
     * registered.
     */
    @BuildStep
    NativeImageResourceBundleBuildItem securityResourceBundle() {
        return new NativeImageResourceBundleBuildItem("sun.security.util.resources.security", "java.base");
    }
}
