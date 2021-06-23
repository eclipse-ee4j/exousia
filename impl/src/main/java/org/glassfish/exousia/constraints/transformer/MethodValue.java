/*
 * Copyright (c) 1997, 2018 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.exousia.constraints.transformer;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.List;

/**
 * @author Harpreet Singh
 * @author Jean-Francois Arcand
 * @author Ron Monzillo
 * @author Arjan Tijms (refactoring)
 */
public class MethodValue extends ConstraintValue {

    private static final List<String> methodNames = new ArrayList<>();

    int index;

    MethodValue(String methodName) {
        index = getMethodIndex(methodName);
    }

    MethodValue(String methodName, ConstraintValue constraint) {
        index = getMethodIndex(methodName);
        setValue(constraint);
    }

    static String getMethodName(int index) {
        synchronized (methodNames) {
            return methodNames.get(index);
        }
    }

    static int getMethodIndex(String name) {
        synchronized (methodNames) {
            int index = methodNames.indexOf(name);
            if (index < 0) {
                index = methodNames.size();
                methodNames.add(index, name);
            }
            return index;
        }
    }

    static String getActions(BitSet methodSet) {
        if (methodSet == null || methodSet.isEmpty()) {
            return null;
        }

        StringBuilder actions = null;

        for (int i = methodSet.nextSetBit(0); i >= 0; i = methodSet.nextSetBit(i + 1)) {
            if (actions == null) {
                actions = new StringBuilder();
            } else {
                actions.append(",");
            }
            actions.append(getMethodName(i));
        }

        return (actions == null ? null : actions.toString());
    }

    static BitSet encodeMethodsToBits(Collection<String> methods) {
        BitSet methodSet = new BitSet();

        for (String method : methods) {
            if (method == null) {
                throw new IllegalArgumentException("constraint translation error - null method name");
            }
            
            methodSet.set(getMethodIndex(method));
        }

        return methodSet;
    }

    @Override
    public String toString() {
        return "MethodValue( " + getMethodName(index) + super.toString() + " )";
    }
}