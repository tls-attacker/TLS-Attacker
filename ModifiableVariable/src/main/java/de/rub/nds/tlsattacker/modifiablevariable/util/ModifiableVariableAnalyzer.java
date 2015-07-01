/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.modifiablevariable.util;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.ReflectionHelper;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ModifiableVariableAnalyzer {

    private static final Logger LOGGER = LogManager.getLogger(ModifiableVariableAnalyzer.class);

    /**
     * Maximum recursion that is used by the search for modifiable variable
     * holders. If this value would not be restricted, method
     * getAllModifiableVariableHolders would search recursively for the holders,
     * until a stack overflow would appear.
     *
     * For example, java.lang.Integer contains MIN_VALUE field that is of type
     * Integer and is not null. Searching in the Integer object would result
     * into an overflow.
     */
    private static final int MAX_DEPTH = 3;

    /**
     * Lists all the modifiable variables declared in the given class
     *
     * @param object
     * @return
     */
    public static List<Field> getAllModifiableVariableFields(Object object) {
        return ReflectionHelper.getFieldsUpTo(object.getClass(), null, ModifiableVariable.class);
    }

    /**
     * Returns a random field representing a modifiable variable in the given
     * class
     *
     * @param object
     * @return
     */
    public static Field getRandomModifiableVariableField(Object object) {
        List<Field> fields = getAllModifiableVariableFields(object);
        int randomField = RandomHelper.getRandom().nextInt(fields.size());
        return fields.get(randomField);
    }

    /**
     * Returns true if the given object contains a modifiable variable
     *
     * @param object
     * @return
     */
    public static boolean isModifiableVariableHolder(Object object) {
        List<Field> fields = getAllModifiableVariableFields(object);
        return !fields.isEmpty();
    }

    /**
     * Returns a list of all ModifiableVariableFields (object-field
     * representations) for a given object.
     *
     * @param object
     * @return
     */
    public static List<ModifiableVariableField> getAllModifiableVariableFieldsRecursively(Object object) {
        List<ModifiableVariableHolder> holders = getAllModifiableVariableHoldersRecursively(object);
        List<ModifiableVariableField> fields = new LinkedList<>();
        for (ModifiableVariableHolder holder : holders) {
            for (Field f : holder.getFields()) {
                fields.add(new ModifiableVariableField(holder.getObject(), f));
            }
        }
        return fields;
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance
     *
     * @param object
     * @return
     */
    public static List<ModifiableVariableHolder> getAllModifiableVariableHoldersRecursively(Object object) {
        return getAllModifiableVariableHoldersRecursively(object, MAX_DEPTH);
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance.
     *
     * @param object
     * @return
     */
    private static List<ModifiableVariableHolder> getAllModifiableVariableHoldersRecursively(Object object,
            int currentDepth) {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (object != null) {
            List<Field> modFields = getAllModifiableVariableFields(object);
            if (!modFields.isEmpty()) {
                System.out.println("found: " + currentDepth);
                holders.add(new ModifiableVariableHolder(object, modFields));
            }
            List<Field> allFields = ReflectionHelper.getFieldsUpTo(object.getClass(), null, null);
            for (Field f : allFields) {
                try {
                    HoldsModifiableVariable holderProperty = f.getAnnotation(HoldsModifiableVariable.class);
                    f.setAccessible(true);
                    Object possibleHolder = f.get(object);
                    if (possibleHolder != null && possibleHolder.getClass() != Object.class) {
                        if (holderProperty != null) {
                            System.out.println("before: " + currentDepth);
                            currentDepth = holderProperty.depth();
                            System.out.println("after: " + currentDepth);
                            System.out.println(possibleHolder.getClass());
                        }
                        if (currentDepth != 0) {
                            List<ModifiableVariableHolder> h = getAllModifiableVariableHoldersRecursively(possibleHolder, currentDepth - 1);
                            if(h.size() != 0) {
                                System.out.println(f.getName());
                            }
                            holders.addAll(getAllModifiableVariableHoldersRecursively(possibleHolder, currentDepth - 1));
                        }
                    }
                } catch (IllegalAccessException | IllegalArgumentException ex) {
                    LOGGER.info("Accessing field {} of type {} not possible", f.getName(), f.getType());
                }
            }
        }
        return holders;
    }

    // /**
    // * Returns a random modifiable variable holder
    // *
    // * @return
    // */
    // public ModifiableVariableHolder getRandomModifiableVariableHolder() {
    // List<ModifiableVariableHolder> holders =
    // getAllModifiableVariableHolders();
    // int randomHolder = RandomHelper.getRandom().nextInt(holders.size());
    // return holders.get(randomHolder);
    // }
}
