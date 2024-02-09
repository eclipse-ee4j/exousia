/*
 * Copyright (c) 2023 Contributors to the Eclipse Foundation.
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

module org.glassfish.exousia {
    
    exports org.glassfish.exousia;
    exports org.glassfish.exousia.constraints;
    exports org.glassfish.exousia.constraints.transformer;
    exports org.glassfish.exousia.mapping;
    exports org.glassfish.exousia.modules.def;
    exports org.glassfish.exousia.modules.locked;
    exports org.glassfish.exousia.permissions;
    opens org.glassfish.exousia;
    opens org.glassfish.exousia.constraints;
    opens org.glassfish.exousia.constraints.transformer;
    opens org.glassfish.exousia.mapping;
    opens org.glassfish.exousia.modules.def;
    opens org.glassfish.exousia.modules.locked;
    opens org.glassfish.exousia.permissions;
    requires jakarta.servlet;
    requires jakarta.security.jacc;
    requires java.logging;
    requires org.javassist;
    requires static java.management;
}
