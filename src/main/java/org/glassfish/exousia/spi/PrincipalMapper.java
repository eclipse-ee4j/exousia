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
package org.glassfish.exousia.spi;

import static java.util.Arrays.asList;

import java.security.Principal;
import java.util.List;

import javax.security.auth.Subject;

/**
 * 
 * @author Arjan Tijms
 *
 */
public interface PrincipalMapper {
    
    default List<String> getMappedRoles(Principal[] principals, Subject subject) {
        return getMappedRoles(asList(principals), subject);
    }
    
    List<String> getMappedRoles(Iterable<Principal> principals, Subject subject);
    
    default boolean isAnyAuthenticatedUserRoleMapped() {
        return false;
    }

}
