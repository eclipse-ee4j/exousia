/*
 * Copyright (c) 2020, 2021 OmniFaces. All rights reserved.
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
package org.glassfish.exousia.mapping;

public class SecurityRoleRef {

    /**
     * The role scoped to a specific servlet, and the role used in <code>isUser/CallerInRole</code> methods.
     */
    private final String roleName;

    /**
     * The "global" application role, as defined by <code>declareRoles</code> or <code>security-role</code>
     */
    private final String roleLink;

    public SecurityRoleRef(String roleName, String roleLink) {
        this.roleName = roleName;
        this.roleLink = roleLink;
    }

    public String getRoleName() {
        return roleName;
    }


    public String getRoleLink() {
        return roleLink;
    }

}