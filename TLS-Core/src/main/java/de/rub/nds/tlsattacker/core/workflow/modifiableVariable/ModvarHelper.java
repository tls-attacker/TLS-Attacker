/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.modifiableVariable;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.modifiablevariable.util.ModifiableVariableListHolder;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.modifiablevariable.util.ReflectionHelper;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A helper class which implements useful methods to modify a TestVector on a higher level. */
public class ModvarHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Random random;

    public ModvarHelper() {
        random = RandomHelper.getRandom();
    }

    /**
     * Chooses a random modifiableVariableField from a List of modifiableVariableFields
     *
     * @param fields A list of Fields to pick from
     * @return A Random field
     */
    public ModifiableVariableField pickRandomField(List<ModifiableVariableField> fields) {

        int fieldNumber = random.nextInt(fields.size());
        return fields.get(fieldNumber);
    }

    public List<ModifiableVariableField> getAllNonNullSentFieldsOfType(
            WorkflowTrace trace, Class type) {
        List<ModifiableVariableField> allNonNullSentFields = getAllNonNullSentFields(trace);
        List<ModifiableVariableField> resultFields = new LinkedList<>();
        for (ModifiableVariableField field : allNonNullSentFields) {
            try {
                if (field.getModifiableVariable().getClass().equals(type)) {
                    resultFields.add(field);
                }
            } catch (IllegalArgumentException | IllegalAccessException ex) {
                LOGGER.warn("Could not retrieved Modvar");
                LOGGER.debug(ex);
            }
        }

        return resultFields;
    }

    public List<ModifiableVariableField> getAllNonNullSentFields(WorkflowTrace trace) {
        List<ModifiableVariableListHolder> holderList =
                getSendModifiableVariableHoldersRecursively(trace);
        List<ModifiableVariableField> allFields = new LinkedList<>();
        for (ModifiableVariableListHolder holder : holderList) {
            for (Field field : holder.getFields()) {
                allFields.add(new ModifiableVariableField(holder.getObject(), field));
            }
        }

        List<ModifiableVariableField> filteredList = new LinkedList<>();
        for (ModifiableVariableField field : allFields) {
            try {
                if (field.getModifiableVariable() != null) {
                    filteredList.add(field);
                }
            } catch (IllegalArgumentException | IllegalAccessException ex) {
                LOGGER.warn("Could not access field!");
                throw new WorkflowExecutionException("Could not access Field!", ex);
            }
        }
        return filteredList;
    }

    public List<ModifiableVariableField> getAllSentFields(WorkflowTrace trace) {
        List<ModifiableVariableListHolder> holderList =
                getSendModifiableVariableHoldersRecursively(trace);
        List<ModifiableVariableField> allFields = new LinkedList<>();
        for (ModifiableVariableListHolder holder : holderList) {
            for (Field field : holder.getFields()) {
                allFields.add(new ModifiableVariableField(holder.getObject(), field));
            }
        }

        return allFields;
    }

    /**
     * Returns a list of all ModifiableVariableHolders from the WorkflowTrace that we send
     *
     * @param trace Trace to search in
     * @return A list of all ModifieableVariableHolders
     */
    public List<ModifiableVariableHolder> getSentModifiableVariableHolders(WorkflowTrace trace) {
        List<ProtocolMessage> protocolMessages = WorkflowTraceUtil.getAllSendMessages(trace);
        List<ModifiableVariableHolder> result = new LinkedList<>();
        for (ProtocolMessage pm : protocolMessages) {
            result.addAll(pm.getAllModifiableVariableHolders());
        }
        return result;
    }

    /**
     * Returns a list of all ModifiableVariableHolders from the WorkflowTrace that we send
     *
     * @param trace Trace to search in
     * @return A list of all ModifieableVariableHolders
     */
    public List<ModifiableVariableListHolder> getReceivedModifiableVariableHoldersRecursively(
            WorkflowTrace trace) {
        List<ProtocolMessage> protocolMessages = WorkflowTraceUtil.getAllReceivedMessages(trace);
        List<ModifiableVariableListHolder> result = new LinkedList<>();
        for (ProtocolMessage pm : protocolMessages) {
            result.addAll(
                    ModifiableVariableAnalyzer.getAllModifiableVariableHoldersRecursively(pm));
        }

        return result;
    }

    public List<ModifiableVariableListHolder> getSendModifiableVariableHoldersRecursively(
            WorkflowTrace trace) {
        List<ProtocolMessage> protocolMessages = WorkflowTraceUtil.getAllSendMessages(trace);
        List<ModifiableVariableListHolder> result = new LinkedList<>();
        for (ProtocolMessage pm : protocolMessages) {
            result.addAll(
                    ModifiableVariableAnalyzer.getAllModifiableVariableHoldersRecursively(pm));
        }

        return result;
    }

    /**
     * Tries to find all ModifieableVariableFields in an Object
     *
     * @param object Object to search in
     * @return List of all ModifieableVariableFields in an object
     */
    public List<ModifiableVariableField> getAllModifiableVariableFieldsRecursively(Object object) {
        List<ModifiableVariableListHolder> holders =
                getAllModifiableVariableHoldersRecursively(object);
        List<ModifiableVariableField> fields = new LinkedList<>();
        for (ModifiableVariableListHolder holder : holders) {
            // if (!(holder.getObject() instanceof ProtocolMessage))
            {
                for (Field f : holder.getFields()) {
                    fields.add(new ModifiableVariableField(holder.getObject(), f));
                }
            }
        }
        return fields;
    }

    /**
     * Returns a list of all the modifiable variable holders in the object, including this instance.
     *
     * @param object Object to search in
     * @return List of all ModifieableVariableListHolders
     */
    public List<ModifiableVariableListHolder> getAllModifiableVariableHoldersRecursively(
            Object object) {
        List<ModifiableVariableListHolder> holders = new LinkedList<>();
        List<Field> modFields = ModifiableVariableAnalyzer.getAllModifiableVariableFields(object);
        if (!modFields.isEmpty()) {
            holders.add(new ModifiableVariableListHolder(object, modFields));
        }
        List<Field> allFields = ReflectionHelper.getFieldsUpTo(object.getClass(), null, null);
        allFields.forEach(
                (f) -> {
                    try {
                        HoldsModifiableVariable holdsVariable =
                                f.getAnnotation(HoldsModifiableVariable.class);
                        f.setAccessible(true);
                        Object possibleHolder = f.get(object);
                        if (possibleHolder != null && holdsVariable != null) {
                            if (possibleHolder instanceof List) {
                                holders.addAll(
                                        ModifiableVariableAnalyzer
                                                .getAllModifiableVariableHoldersFromList(
                                                        (List) possibleHolder));
                            } else if (possibleHolder.getClass().isArray()) {
                                holders.addAll(
                                        ModifiableVariableAnalyzer
                                                .getAllModifiableVariableHoldersFromArray(
                                                        (Object[]) possibleHolder));
                            } else {
                                if (ProtocolMessage.class.isInstance(object)) {
                                    // LOGGER.info("Skipping {}",
                                    // possibleHolder.getClass());
                                } else {
                                    holders.addAll(
                                            ModifiableVariableAnalyzer
                                                    .getAllModifiableVariableHoldersRecursively(
                                                            possibleHolder));
                                }
                            }
                        }
                    } catch (IllegalAccessException | IllegalArgumentException ex) {
                        LOGGER.error("Could not access Field!", ex);
                    }
                });
        return holders;
    }
}
