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
package org.omnifaces.exousia.permissions;

import java.security.Permissions;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 * @author Arjan Tijms
 *
 */
public class JakartaPermissions {

    // Permissions for resources nobody can access
    private final Permissions excluded = new Permissions();

    // Permissions for resources everybody can access
    private final Permissions unchecked = new Permissions();

    // Permissions for resources that require a role
    private final Map<String, Permissions> perRole = new HashMap<String, Permissions>();
    
    public Permissions getExcluded() {
        return excluded;
    }

    public Permissions getUnchecked() {
        return unchecked;
    }

    public Map<String, Permissions> getPerRole() {
        return perRole;
    }
    
}
