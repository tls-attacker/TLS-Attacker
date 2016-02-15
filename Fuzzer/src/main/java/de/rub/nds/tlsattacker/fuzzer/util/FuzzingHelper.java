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
package de.rub.nds.tlsattacker.fuzzer.util;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableListHolder;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ModificationException;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.ReflectionHelper;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class FuzzingHelper {

    private static final Logger LOGGER = LogManager.getLogger(FuzzingHelper.class);

    public static final int MAX_MODIFICATION_COUNT = 5;

    private FuzzingHelper() {

    }

    public static boolean executeFuzzingUnit(int percentage) {
        int random = RandomHelper.getRandom().nextInt(100);
        return (percentage > random);
    }

    /**
     * Picks a random workflow message, picks a random variable and executes a
     * modification. In a case a pattern was used, it matches the picked
     * variable contains this pattern.
     *
     * @param workflow
     * @param connectionEnd
     * @param pattern
     */
    public static void executeRandomModifiableVariableModification(WorkflowTrace workflow, ConnectionEnd connectionEnd,
            String pattern) {
        Field f = null;
        ModifiableVariableHolder holder = null;
        while (f == null) {
            holder = getRandomModifiableVariableHolder(workflow, connectionEnd);
            Field randomField = holder.getRandomModifiableVariableField();
            if (pattern == null || randomField.getName().toLowerCase().contains(pattern)) {
                f = randomField;
            }
        }
        LOGGER.debug("Executing random variable modification on field {} in {}", f, holder);
        executeModifiableVariableModification(holder, f);
    }

    /**
     * Picks a random workflow message, picks a random variable and executes a
     * modification.
     *
     * @param workflow
     * @param connectionEnd
     * @param allowedTypes
     * @param allowedFormats
     * @param whitelistRegex
     * @param blacklistRegex
     */
    public static void executeRandomModifiableVariableModification(WorkflowTrace workflow, ConnectionEnd connectionEnd,
            List<ModifiableVariableProperty.Type> allowedTypes, List<ModifiableVariableProperty.Format> allowedFormats,
            String whitelistRegex, String blacklistRegex) {
        Field f = null;
        ModifiableVariableHolder holder = null;
        if (workflow.getClientMessages().isEmpty()) {
            return;
        }
        while (f == null) {
            holder = getRandomModifiableVariableHolder(workflow, connectionEnd);
            Field randomField = holder.getRandomModifiableVariableField();
            if (isModifiableVariableModificationAllowed(randomField, allowedTypes, allowedFormats, whitelistRegex,
                    blacklistRegex)) {
                f = randomField;
            }
        }
        LOGGER.debug("Executing random variable modification on field {}", f);
        executeModifiableVariableModification(holder, f);
    }

    public static boolean isModifiableVariableModificationAllowed(Field randomField,
            List<ModifiableVariableProperty.Type> allowedTypes, List<ModifiableVariableProperty.Format> allowedFormats,
            String whitelistRegex, String blacklistRegex) {
        ModifiableVariableProperty property = randomField.getAnnotation(ModifiableVariableProperty.class);
        if (property != null) {
            if ((allowedTypes == null || allowedTypes.contains(property.type()))
                    && (allowedFormats == null || allowedFormats.contains(property.format()))
                    && (whitelistRegex == null || randomField.getName().matches(whitelistRegex))
                    && (blacklistRegex == null || !randomField.getName().matches(blacklistRegex))) {
                return true;
            }
        }
        return false;
    }

    public static boolean isModifiableVariableFromMyPeer(ModifiableVariableField field, ConnectionEnd peer) {
        if (field.getObject() instanceof ProtocolMessage) {
            System.out.print("test");
        }
        return false;
    }

    /**
     * Picks a random modifiable variable and executes a random modification on
     * this variable.
     *
     * @param object
     */
    public static void executeRandomModifiableVariableModification(ModifiableVariableHolder object) {
        Field field = object.getRandomModifiableVariableField();
        executeModifiableVariableModification(object, field);
    }

    /**
     * Executes a random modification on a defined field. Source:
     * http://stackoverflow.com/questions/1868333/how-can-i-determine-the
     * -type-of-a-generic-field-in-java
     *
     * @param object
     * @param field
     */
    public static void executeModifiableVariableModification(ModifiableVariableHolder object, Field field) {
        try {
            // Type type = field.getGenericType();
            // ParameterizedType pType = (ParameterizedType) type;
            // String typeString = ((Class)
            // pType.getActualTypeArguments()[0]).getSimpleName();
            // LOGGER.debug("Modifying field {} of type {} from the following class: {} ",
            // field.getName(), typeString,
            // object.getClass().getSimpleName());
            field.setAccessible(true);
            ModifiableVariable mv = (ModifiableVariable) field.get(object);
            if (mv == null) {
                mv = (ModifiableVariable) field.getType().getDeclaredConstructors()[0].newInstance();
            }
            mv.createRandomModificationAtRuntime();
            LOGGER.debug("Modifying field {} of type {} from the following class: {} ", field.getName(),
                    field.getType(), object.getClass().getSimpleName());
            field.set(object, mv);
        } catch (IllegalAccessException | IllegalArgumentException | InstantiationException | InvocationTargetException ex) {
            throw new ModificationException(ex.getLocalizedMessage(), ex);
        }
    }

    /**
     * Returns a list of all Modifiable variable holders from the workflow
     * trace. Currently, it returns all protocol messages.
     *
     * @param trace
     * @return
     */
    public static List<ModifiableVariableHolder> getModifiableVariableHolders(WorkflowTrace trace) {
        List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
        List<ModifiableVariableHolder> result = new LinkedList<>();
        for (ProtocolMessage pm : protocolMessages) {
            result.addAll(pm.getAllModifiableVariableHolders());
        }
        return result;
    }

    /**
     * Returns a list of all Modifiable variable holders from the workflow
     * trace, for a specific message issuer.
     *
     * @param trace
     * @param messageIssuer
     * @return
     */
    public static List<ModifiableVariableHolder> getModifiableVariableHolders(WorkflowTrace trace,
            ConnectionEnd messageIssuer) {
        List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
        List<ModifiableVariableHolder> result = new LinkedList<>();
        for (ProtocolMessage pm : protocolMessages) {
            if (pm.getMessageIssuer() == messageIssuer) {
                result.addAll(pm.getAllModifiableVariableHolders());
            }
        }
        return result;
    }

    /**
     * Returns a random Modifiable variable holder from the workflow trace
     *
     * @param trace
     * @param messageIssuer
     * @return
     */
    public static ModifiableVariableHolder getRandomModifiableVariableHolder(WorkflowTrace trace,
            ConnectionEnd messageIssuer) {
        List<ModifiableVariableHolder> holders = getModifiableVariableHolders(trace, messageIssuer);
        int randomHolder = RandomHelper.getRandom().nextInt(holders.size());
        return holders.get(randomHolder);
    }

    /**
     * Adds random records to the workflow trace
     *
     * @param trace
     * @param messageIssuer
     */
    public static void addRecordsAtRandom(WorkflowTrace trace, ConnectionEnd messageIssuer) {
        List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
        Random random = RandomHelper.getRandom();
        int recordsNumber = random.nextInt(4);
        int i = 0;
        while (recordsNumber > 0 && i < MAX_MODIFICATION_COUNT) {
            i++;
            int randomPM = random.nextInt(protocolMessages.size());
            ProtocolMessage pm = protocolMessages.get(randomPM);
            if (pm.getMessageIssuer() == messageIssuer) {
                Record r = new Record();
                r.setMaxRecordLengthConfig(random.nextInt(50));
                pm.addRecord(r);
                recordsNumber--;
                LOGGER.debug("Adding a new record to {}", pm.getClass());
            }
        }
    }

    public static void removeRandomProtocolMessage(WorkflowTrace trace, ConnectionEnd messageIssuer) {
        List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
        Random random = RandomHelper.getRandom();
        int i = 0;
        while (i < MAX_MODIFICATION_COUNT) {
            i++;
            int position = random.nextInt(protocolMessages.size());
            if (trace.getProtocolMessages().get(position).getMessageIssuer() == messageIssuer) {
                trace.getProtocolMessages().remove(position);
                return;
            }
        }
    }

    public static void addRandomProtocolMessage(WorkflowTrace trace, ConnectionEnd messageIssuer) {
        List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
        Random random = RandomHelper.getRandom();
        int position = random.nextInt(protocolMessages.size());
        int protocolMessageType = random.nextInt(8);
        ProtocolMessage pm = null;
        switch (protocolMessageType) {
            case 0:
                pm = new ClientHelloMessage(messageIssuer);
                break;
            case 1:
                pm = new RSAClientKeyExchangeMessage(messageIssuer);
                break;
            case 2:
                pm = new ChangeCipherSpecMessage(messageIssuer);
                break;
            case 3:
                pm = new FinishedMessage(messageIssuer);
                break;
            case 4:
                pm = new ApplicationMessage(messageIssuer);
                break;
            case 5:
                pm = new HeartbeatMessage(messageIssuer);
                break;
            case 6:
                pm = new ServerHelloMessage(messageIssuer);
                break;
            case 7:
                pm = new ServerHelloDoneMessage(messageIssuer);
                break;
        }
        if (pm != null) {
            protocolMessages.add(position, pm);
        }
    }

    public static void duplicateRandomProtocolMessage(WorkflowTrace trace, ConnectionEnd messageIssuer) {
        List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
        Random random = RandomHelper.getRandom();
        int insertPosition = random.nextInt(protocolMessages.size());
        ProtocolMessage pm = null;
        while (pm == null) {
            int takePosition = random.nextInt(protocolMessages.size());
            if (protocolMessages.get(takePosition).getMessageIssuer() == messageIssuer) {
                pm = (ProtocolMessage) UnoptimizedDeepCopy.copy(protocolMessages.get(takePosition));
            }
        }
        protocolMessages.add(insertPosition, pm);
        LOGGER.debug("Duplicating {} \n  and inserting it at position {}", pm.getClass(), insertPosition);
    }

    public static ProtocolMessage getRandomProtocolMessage(WorkflowTrace trace, ConnectionEnd messageIssuer) {
        List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
        Random random = RandomHelper.getRandom();
        ProtocolMessage pm = null;
        while (true) {
            int position = random.nextInt(protocolMessages.size());
            if (protocolMessages.get(position).getMessageIssuer() == messageIssuer) {
                return protocolMessages.get(position);
            }
        }
    }

    /**
     * Returns a list of all ModifiableVariableFields (object-field
     * representations) for a given object.
     *
     * @param object
     * @return
     */
    public static List<ModifiableVariableField> getAllModifiableVariableFieldsRecursively(Object object, ConnectionEnd myPeer) {
        List<ModifiableVariableListHolder> holders = getAllModifiableVariableHoldersRecursively(object, myPeer);
        List<ModifiableVariableField> fields = new LinkedList<>();
        for (ModifiableVariableListHolder holder : holders) {
            if (!(holder.getObject() instanceof ProtocolMessage) || ((ProtocolMessage) holder.getObject()).getMessageIssuer() == myPeer) {
                for (Field f : holder.getFields()) {
                    fields.add(new ModifiableVariableField(holder.getObject(), f));
                }
            }
        }
        return fields;
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance.
     *
     * @param object
     * @return
     */
    public static List<ModifiableVariableListHolder> getAllModifiableVariableHoldersRecursively(Object object, ConnectionEnd myPeer) {
        List<ModifiableVariableListHolder> holders = new LinkedList<>();
        List<Field> modFields = ModifiableVariableAnalyzer.getAllModifiableVariableFields(object);
        if (!modFields.isEmpty()) {
            holders.add(new ModifiableVariableListHolder(object, modFields));
        }
        List<Field> allFields = ReflectionHelper.getFieldsUpTo(object.getClass(), null, null);
        for (Field f : allFields) {
            try {
                HoldsModifiableVariable holdsVariable = f.getAnnotation(HoldsModifiableVariable.class);
                f.setAccessible(true);
                Object possibleHolder = f.get(object);
                if (possibleHolder != null && holdsVariable != null) {
                    if (possibleHolder instanceof List) {
                        holders.addAll(ModifiableVariableAnalyzer.getAllModifiableVariableHoldersFromList((List) possibleHolder));
                    } else if (possibleHolder.getClass().isArray()) {
                        holders.addAll(ModifiableVariableAnalyzer.getAllModifiableVariableHoldersFromArray((Object[]) possibleHolder));
                    } else {
                        if (ProtocolMessage.class.isInstance(object) && ((ProtocolMessage) possibleHolder).getMessageIssuer() != myPeer) {
                            LOGGER.info("Skipping {}", possibleHolder.getClass());
                        } else {
                            holders.addAll(ModifiableVariableAnalyzer.getAllModifiableVariableHoldersRecursively(possibleHolder));
                        }
                    }
                }
            } catch (IllegalAccessException | IllegalArgumentException ex) {
                LOGGER.info("Accessing field {} of type {} not possible: {}", f.getName(), f.getType(), ex.toString());
            }
        }
        return holders;
    }

}
