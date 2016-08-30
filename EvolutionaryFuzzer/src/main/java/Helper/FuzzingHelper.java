/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Helper;

import Modification.AddMessageModification;
import Modification.AddRecordModification;
import Modification.AddMessageFlightModification;
import Modification.AddToggleEncrytionActionModification;
import Modification.DuplicateMessageModification;
import Modification.ModifyFieldModification;
import Modification.RemoveMessageModification;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableListHolder;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ModificationException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ToggleEncryptionAction;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.ReflectionHelper;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;

public class FuzzingHelper {

    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(FuzzingHelper.class
	    .getName());

    /**
     *
     */
    public static final int MAX_MODIFICATION_COUNT = 5;

    public static ModifiableVariableField pickRandomField(List<ModifiableVariableField> fields) {
	Random r = new Random();
	int fieldNumber = r.nextInt(fields.size());
	return fields.get(fieldNumber);
    }

    /**
     * Returns a list of all Modifiable variable holders from the workflow trace
     * that we send
     * 
     * @param trace
     * @return
     */
    public static List<ModifiableVariableHolder> getModifiableVariableHolders(WorkflowTrace trace) {
	List<ProtocolMessage> protocolMessages = trace.getAllConfiguredSendMessages();
	List<ModifiableVariableHolder> result = new LinkedList<>();
	for (ProtocolMessage pm : protocolMessages) {
	    result.addAll(pm.getAllModifiableVariableHolders());
	}
	return result;
    }

    public static List<ModifiableVariableField> getAllModifiableVariableFieldsRecursively(Object object) {
	List<ModifiableVariableListHolder> holders = getAllModifiableVariableHoldersRecursively(object);
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
     * Executes a random modification on a defined field. Source:
     * http://stackoverflow.com/questions/1868333/how-can-i-determine-the
     * -type-of-a-generic-field-in-java
     * 
     * @param object
     * @param field
     */
    public static ModifyFieldModification executeModifiableVariableModification(ModifiableVariableHolder object,
	    Field field) {
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

	    field.set(object, mv);
	    return new ModifyFieldModification(field.getName(), object);
	} catch (IllegalAccessException | IllegalArgumentException | InstantiationException | InvocationTargetException ex) {
	    throw new ModificationException(ex.getLocalizedMessage(), ex);
	}
    }

    /**
     * Adds random records to the workflow trace
     * 
     * @param trace
     * @param messageIssuer
     */
    public static AddRecordModification addRecordAtRandom(WorkflowTrace trace) {
	List<ProtocolMessage> protocolMessages = trace.getAllConfiguredSendMessages();
	Random random = RandomHelper.getRandom();
	for (int i = 0; i < protocolMessages.size(); i++) {
	    int randomPM = random.nextInt(protocolMessages.size());
	    ProtocolMessage pm = protocolMessages.get(randomPM);
	    Record r = new Record();
	    r.setMaxRecordLengthConfig(random.nextInt(50));// TODO can we make
							   // this more crazy?
	    pm.addRecord(r);
	    return new AddRecordModification(pm);

	}
	return null;
    }

    public static RemoveMessageModification removeRandomMessage(WorkflowTrace tempTrace) {
	SendAction action = getRandomSendAction(tempTrace);
	if (action.getConfiguredMessages().size() <= 1) {
	    // We dont remove the last message from a flight
	    return null;
	}
	Random r = new Random();
	int index = r.nextInt(action.getConfiguredMessages().size());
	ProtocolMessage message = action.getConfiguredMessages().get(index);
	action.getConfiguredMessages().remove(index);
	return new RemoveMessageModification(message, action, index);
    }

    /**
     * Adds a new SendAction followed by a new Receive Action. The SendAction
     * initially contains a random message, and the receive action only contains
     * an arbitary message
     * 
     * @param tempTrace
     * @return
     */
    public static AddMessageFlightModification addMessageFlight(WorkflowTrace tempTrace) {
	SendAction sendAction = new SendAction(generateRandomMessage());
	ReceiveAction receiveAction = new ReceiveAction(new ArbitraryMessage());
	tempTrace.add(sendAction);
	tempTrace.add(receiveAction);
	return new AddMessageFlightModification(sendAction, receiveAction);
    }

    /**
     * Adds a random Message to a random SendAction
     * 
     * @param tempTrace
     * @return
     */
    public static AddMessageModification addRandomMessage(WorkflowTrace tempTrace) {
	SendAction action = getRandomSendAction(tempTrace);
	if (action == null) {
	    return null;
	} else {
	    ProtocolMessage message = generateRandomMessage();
	    action.getConfiguredMessages().add(message);
	    return new AddMessageModification(message, action);
	}
    }

    private static SendAction getRandomSendAction(WorkflowTrace tempTrace) {
	Random r = new Random();
	List<SendAction> sendActions = tempTrace.getSendActions();
	return sendActions.get(r.nextInt(sendActions.size()));
    }

    private static ProtocolMessage generateRandomMessage() {
	ProtocolMessage message = null;
	Random r = new Random();
	do {

	    switch (r.nextInt(18)) {
		case 0:
		    message = new AlertMessage();
		    break;
		case 1:
		    message = new ApplicationMessage();
		    break;
		case 2:
		    message = new CertificateMessage();
		    break;
		case 3:
		    message = new CertificateRequestMessage();
		    break;
		case 4:
		    message = new CertificateVerifyMessage();
		    break;
		case 5:
		    message = new ChangeCipherSpecMessage();
		    break;
		case 6:
		    message = new ClientHelloDtlsMessage();
		    LinkedList<CipherSuite> list = new LinkedList<>();
		    int limit = new Random().nextInt(0xFF);

		    for (int i = 0; i < limit; i++) {
			CipherSuite suite = null;

			do {

			    suite = CipherSuite.getRandom();

			} while (suite == null);
			list.add(suite);
		    }
		    ArrayList<CompressionMethod> compressionList = new ArrayList<>();
		    compressionList.add(CompressionMethod.NULL);
		    ((ClientHelloMessage) message).setSupportedCipherSuites(list);
		    ((ClientHelloMessage) message).setSupportedCompressionMethods(compressionList);
		    break;
		case 7:
		    message = new ClientHelloMessage();
		    list = new LinkedList<>();
		    limit = new Random().nextInt(0xFF);
		    for (int i = 0; i < limit; i++) {
			CipherSuite suite = null;
			do {
			    suite = CipherSuite.getRandom();
			} while (suite == null);
			list.add(suite);
		    }
		    compressionList = new ArrayList<>();
		    compressionList.add(CompressionMethod.NULL);
		    ((ClientHelloMessage) message).setSupportedCipherSuites(list);
		    ((ClientHelloMessage) message).setSupportedCompressionMethods(compressionList);
		    break;
		case 8:
		    message = new DHClientKeyExchangeMessage();
		    break;
		case 9:
		    message = new HelloVerifyRequestMessage();
		    break;
		case 10:
		    message = new DHEServerKeyExchangeMessage();
		    break;
		case 11:
		    message = new ECDHClientKeyExchangeMessage();
		    break;
		case 12:
		    message = new ECDHEServerKeyExchangeMessage();
		    break;
		case 13:
		    message = new FinishedMessage();
		    break;
		case 14:
		    message = new HeartbeatMessage();
		    break;
		case 15:
		    message = new RSAClientKeyExchangeMessage();
		    break;
		case 16:
		    message = new ServerHelloDoneMessage();

		    break;
		case 17:
		    message = new HelloRequestMessage();
		    break;
	    }
	} while (message == null);
	return message;
    }

    /**
     * 
     * @param trace
     * @param messageIssuer
     */
    public static DuplicateMessageModification duplicateRandomProtocolMessage(WorkflowTrace trace) {
	Random r = new Random();
	ProtocolMessage message = null;
	List<ProtocolMessage> protocolMessages = trace.getAllConfiguredSendMessages();
	if (protocolMessages.size() > 0) {
	    message = (ProtocolMessage) UnoptimizedDeepCopy
		    .copy(protocolMessages.get(r.nextInt(protocolMessages.size())));
	} else {
	    return null;
	}
	SendAction action = getRandomSendAction(trace);
	int insertPosition = r.nextInt(action.getConfiguredMessages().size());

	action.getConfiguredMessages().add(insertPosition, message);
	return new DuplicateMessageModification(message, action, insertPosition);
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance.
     * 
     * @param object
     * @param myPeer
     * @return
     */
    public static List<ModifiableVariableListHolder> getAllModifiableVariableHoldersRecursively(Object object) {
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
			holders.addAll(ModifiableVariableAnalyzer
				.getAllModifiableVariableHoldersFromList((List) possibleHolder));
		    } else if (possibleHolder.getClass().isArray()) {
			holders.addAll(ModifiableVariableAnalyzer
				.getAllModifiableVariableHoldersFromArray((Object[]) possibleHolder));
		    } else {
			if (ProtocolMessage.class.isInstance(object)) {
			    // LOGGER.info("Skipping {}",
			    // possibleHolder.getClass());
			} else {
			    holders.addAll(ModifiableVariableAnalyzer
				    .getAllModifiableVariableHoldersRecursively(possibleHolder));
			}
		    }
		}
	    } catch (IllegalAccessException | IllegalArgumentException ex) {
		LOG.log(Level.SEVERE, "Could not access Field!", ex);
	    }
	}
	return holders;
    }

    public static AddToggleEncrytionActionModification addToggleEncrytionActionModification(WorkflowTrace trace)
    {
        TLSAction newAction = new ToggleEncryptionAction();
        List<TLSAction> actionList = trace.getTLSActions();
        Random r = new Random();
        int positon = r.nextInt(actionList.size());
        actionList.add(positon, newAction);
        return new AddToggleEncrytionActionModification(positon);
    }
    private FuzzingHelper() {

    }

}
