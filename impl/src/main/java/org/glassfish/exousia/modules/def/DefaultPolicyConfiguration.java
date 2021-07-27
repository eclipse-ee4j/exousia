/*
 * Copyright (c) 2019, 2021 OmniFaces. All rights reserved.
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
package org.glassfish.exousia.modules.def;
import static org.glassfish.exousia.AuthorizationService.PRINCIPAL_MAPPER;

import org.glassfish.exousia.spi.PrincipalMapper;
import org.glassfish.exousia.spi.impl.DefaultRoleMapper;

import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultPolicyConfiguration
    extends
    DefaultPolicyConfigurationPermissions {

    public DefaultPolicyConfiguration(
        String contextID) {
        super(contextID);
    }

    private PrincipalMapper roleMapper;

    @Override
    public void commit()
        throws PolicyContextException {

        roleMapper = (PrincipalMapper) PolicyContext
            .getContext(
                PRINCIPAL_MAPPER);
        if (roleMapper == null) {
            roleMapper = new DefaultRoleMapper(
                getContextID(),
                getPerRolePermissions()
                    .keySet());
        }
    }

    public PrincipalMapper getRoleMapper() {
        return roleMapper;
    }

}