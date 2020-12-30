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

package org.omnifaces.exousia;

import java.util.function.Supplier;

import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PolicyContextHandler;

/**
 * 
 * @author Arjan Tijms
 */
public class DefaultPolicyContextHandler implements PolicyContextHandler {
    
    private final String key;
    private final String[] keys;
    private final Supplier<? extends Object> contextObjectSupplier;
    
    public DefaultPolicyContextHandler(String key, Supplier<? extends Object> contextObjectSupplier) {
        this.key = key;
        this.keys = new String[] { key };
        this.contextObjectSupplier = contextObjectSupplier;
    }

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        return contextObjectSupplier.get();
    }

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return this.key.equals(key);
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return keys;
    }
    
    
}
