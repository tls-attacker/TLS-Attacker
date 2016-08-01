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

    public static List<ModifiableVariableField> getAllModifiableVariableFieldsRecursively(Object object,
	    ConnectionEnd myPeer) {
	List<ModifiableVariableListHolder> holders = getAllModifiableVariableHoldersRecursively(object, myPeer);
	List<ModifiableVariableField> fields = new LinkedList<>();
	for (ModifiableVariableListHolder holder : holders) {
	    if (!(holder.getObject() instanceof ProtocolMessage)
		    || ((ProtocolMessage) holder.getObject()).getMessageIssuer() == myPeer) {
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
    public static AddRecordModification addRecordAtRandom(WorkflowTrace trace, ConnectionEnd messageIssuer) {
	List<ProtocolMessage> protocolMessages = trace.getProtocolMessages();
	Random random = RandomHelper.getRandom();
	for(int i = 0; i < protocolMessages.size(); i++)
        {
	    int randomPM = random.nextInt(protocolMessages.size());
	    ProtocolMessage pm = protocolMessages.get(randomPM);
	    if (pm.getMessageIssuer() == messageIssuer) {
		Record r = new Record();
		r.setMaxRecordLengthConfig(random.nextInt(50));
		pm.addRecord(r);
		return new AddRecordModification(pm);
	    }
	}
        return null;
    }

    public static RemoveMessageModification removeRandomMessage(WorkflowTrace tempTrace) {
	Random r = new Random();
	List<ProtocolMessage> messages = tempTrace.getProtocolMessages();
	int i = r.nextInt(messages.size());
	ProtocolMessage message = messages.get(i);

	messages.remove(i);
	return new RemoveMessageModification(message, i);
    }

    public static AddMessageModification addRandomMessage(WorkflowTrace tempTrace) {
	ProtocolMessage m = null;
	Random r = new Random();
	do {

	    switch (r.nextInt(18)) {
		case 0:
		    m = new AlertMessage(ConnectionEnd.CLIENT);
		    break;
		case 1:
		    m = new ApplicationMessage(ConnectionEnd.CLIENT);
		    break;
		case 2:
		    m = new CertificateMessage(ConnectionEnd.CLIENT);
		    break;
		case 3:
		    m = new CertificateRequestMessage(ConnectionEnd.CLIENT);
		    break;
		case 4:
		    m = new CertificateVerifyMessage(ConnectionEnd.CLIENT);
		    break;
		case 5:
		    m = new ChangeCipherSpecMessage(ConnectionEnd.CLIENT);
		    break;
		case 6:
		    m = new ClientHelloDtlsMessage(ConnectionEnd.CLIENT);
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
		    ((ClientHelloMessage) m).setSupportedCipherSuites(list);
		    ((ClientHelloMessage) m).setSupportedCompressionMethods(compressionList);
		    break;
		case 7:
		    m = new ClientHelloMessage(ConnectionEnd.CLIENT);
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
		    ((ClientHelloMessage) m).setSupportedCipherSuites(list);
		    ((ClientHelloMessage) m).setSupportedCompressionMethods(compressionList);
		    break;
		case 8:
		    m = new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT);
		    break;
		case 9:
		    m = new HelloVerifyRequestMessage(ConnectionEnd.CLIENT);
		    break;
		case 10:
		    m = new DHEServerKeyExchangeMessage(ConnectionEnd.CLIENT);
		    break;
		case 11:
		    m = new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT);
		    break;
		case 12:
		    m = new ECDHEServerKeyExchangeMessage(ConnectionEnd.CLIENT);
		    break;
		case 13:
		    m = new FinishedMessage(ConnectionEnd.CLIENT);
		    break;
		case 14:
		    m = new HeartbeatMessage(ConnectionEnd.CLIENT);
		    break;
		case 15:
		    m = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
		    break;
		case 16:
		    m = new ServerHelloDoneMessage(ConnectionEnd.CLIENT);

		    break;
		case 17:
		    m = new HelloRequestMessage(ConnectionEnd.CLIENT);
		    break;
	    }
	} while (m == null);
	tempTrace.add(m);
	ProtocolMessage pm = new ArbitraryMessage();
	pm.setMessageIssuer(ConnectionEnd.SERVER);
	tempTrace.add(pm);
	return new AddMessageModification(m);
    }

    /**
     * 
     * @param trace
     * @param messageIssuer
     */
    public static DuplicateMessageModification duplicateRandomProtocolMessage(WorkflowTrace trace,
	    ConnectionEnd messageIssuer) {
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
	return new DuplicateMessageModification(pm, insertPosition);
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance.
     * 
     * @param object
     * @param myPeer
     * @return
     */
    public static List<ModifiableVariableListHolder> getAllModifiableVariableHoldersRecursively(Object object,
	    ConnectionEnd myPeer) {
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
			if (ProtocolMessage.class.isInstance(object)
				&& ((ProtocolMessage) possibleHolder).getMessageIssuer() != myPeer) {
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

    private FuzzingHelper() {

    }

}
