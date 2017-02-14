/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ReflectionHelper {

    /**
     * Source:
     * http://stackoverflow.com/questions/17451506/list-all-private-fields
     * -of-a-java-object Retrieves all fields (all access levels) from all
     * classes up the class hierarchy starting with {@code startClass} stopping
     * with and not including {@code exclusiveParent}. Generally
     * {@code Object.class} should be passed as {@code exclusiveParent}.
     * 
     * @param startClass
     *            the class whose fields should be retrieved
     * @param exclusiveParent
     *            if not null, the base class of startClass whose fields should
     *            not be retrieved.
     * @param filterClass
     *            class that should be used as a type filter
     * @return
     */
    public static List<Field> getFieldsUpTo(Class<?> startClass, Class<?> exclusiveParent, Class<?> filterClass) {
        List<Field> currentClassFields;

        currentClassFields = filterFieldList(Arrays.asList(startClass.getDeclaredFields()), filterClass);

        Class<?> parentClass = startClass.getSuperclass();

        if ((parentClass != null) && ((exclusiveParent == null) || !(parentClass.equals(exclusiveParent)))) {
            List<Field> parentClassFields = getFieldsUpTo(parentClass, exclusiveParent, filterClass);

            currentClassFields.addAll(parentClassFields);
        }

        return currentClassFields;
    }

    /**
     * Takes a list of fields and returns only fields which are subclasses of
     * the filterClass
     * 
     * @param fields
     * @param filterClass
     * @return
     */
    private static List<Field> filterFieldList(List<Field> fields, Class<?> filterClass) {
        List<Field> filteredFields = new LinkedList<>();

        for (Field f : fields) {
            if ((filterClass == null) || filterClass.isAssignableFrom(f.getType())) {
                filteredFields.add(f);
            }
        }

        return filteredFields;
    }

    public static List<Object> getValuesFromFieldList(Object object, List<Field> fields) throws IllegalAccessException {
        List<Object> list = new LinkedList<>();

        for (Field f : fields) {
            f.setAccessible(true);
            list.add(f.get(object));
        }

        return list;
    }

    // /**
    // *
    // * @param object
    // * @param field
    // * @return
    // * @throws IllegalAccessException
    // * @throws java.lang.reflect.InvocationTargetException
    // */
    // public static Object getFieldValue(Object object, Field field) throws
    // IllegalAccessException, IllegalArgumentException,
    // InvocationTargetException {
    // Method[] methods = object.getClass().getMethods();
    // for (Method method : methods) {
    // String name = method.getName();
    // if (name.equalsIgnoreCase("get" + field.getName())) {
    // return method.invoke(object);
    // }
    // }
    // return null;
    // }
    //
    // public static void setFieldValue(Object object, Field field, Object
    // value) throws
    // IllegalAccessException, IllegalArgumentException,
    // InvocationTargetException {
    // Method[] methods = object.getClass().getMethods();
    // for (Method method : methods) {
    // String name = method.getName();
    // if (name.equalsIgnoreCase("set" + field.getName())) {
    // method.invoke(object, value);
    // }
    // }
    // }
    public static Type[] getParameterizedTypes(Object object) {
        Type superclassType = object.getClass().getGenericSuperclass();

        if (!ParameterizedType.class.isAssignableFrom(superclassType.getClass())) {
            return null;
        }

        return ((ParameterizedType) superclassType).getActualTypeArguments();
    }
}
