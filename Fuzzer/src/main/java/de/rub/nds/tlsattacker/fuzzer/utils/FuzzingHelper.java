/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.fuzzer.utils;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ModificationException;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.messages.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.RandomHelper;
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
	while (f == null) {
	    holder = getRandomModifiableVariableHolder(workflow, connectionEnd);
	    Field randomField = holder.getRandomModifiableVariableField();
	    ModifiableVariableProperty property = randomField.getAnnotation(ModifiableVariableProperty.class);
	    if (property != null) {
		if ((allowedTypes == null || allowedTypes.contains(property.type()))
			&& (allowedFormats == null || allowedFormats.contains(property.format()))
			&& (whitelistRegex == null || randomField.getName().matches(whitelistRegex))
			&& (blacklistRegex == null || !randomField.getName().matches(blacklistRegex))) {
		    f = randomField;
		}
	    }
	}
	LOGGER.debug("Executing random variable modification on field {}", f);
	executeModifiableVariableModification(holder, f);
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
	    LOGGER.info("Modifying field {} of type {} from the following class: {} ", field.getName(),
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
	while (recordsNumber > 0) {
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

    public static void addRandomProtocolMessage(WorkflowTrace trace, ConnectionEnd messageIssuer) {
	List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
	Random random = RandomHelper.getRandom();
	int position = random.nextInt(protocolMessages.size());
	int protocolMessageType = random.nextInt(6);
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

}
