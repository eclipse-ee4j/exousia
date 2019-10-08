package org.omnifaces.exousia.constraints;

import java.util.ArrayList;
import java.util.BitSet;

public class MethodValue extends ConstraintValue {

    private static final ArrayList<String> methodNames = new ArrayList();

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

        StringBuffer actions = null;

        for (int i = methodSet.nextSetBit(0); i >= 0; i = methodSet.nextSetBit(i + 1)) {
            if (actions == null) {
                actions = new StringBuffer();
            } else {
                actions.append(",");
            }
            actions.append(getMethodName(i));
        }

        return (actions == null ? null : actions.toString());
    }

    static String[] getMethodArray(BitSet methodSet) {
        if (methodSet == null || methodSet.isEmpty()) {
            return null;
        }

        int size = 0;

        ArrayList<String> methods = new ArrayList();

        for (int i = methodSet.nextSetBit(0); i >= 0; i = methodSet.nextSetBit(i + 1)) {
            methods.add(getMethodName(i));
            size += 1;
        }

        return (String[]) methods.toArray(new String[size]);
    }

    static BitSet methodArrayToSet(String[] methods) {
        BitSet methodSet = new BitSet();

        for (int i = 0; methods != null && i < methods.length; i++) {
            if (methods[i] == null) {
                throw new IllegalArgumentException("constraint translation error - null method name");
            }
            int bit = getMethodIndex(methods[i]);
            methodSet.set(bit);
        }

        return methodSet;
    }

    public String toString() {
        return "MethodValue( " + getMethodName(index) + super.toString() + " )";
    }
}