/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.helper;

import tlsattacker.fuzzer.modification.AddContextActionModification;
import tlsattacker.fuzzer.modification.AddExtensionModification;
import tlsattacker.fuzzer.modification.AddMessageModification;
import tlsattacker.fuzzer.modification.AddRecordModification;
import tlsattacker.fuzzer.modification.AddMessageFlightModification;
import tlsattacker.fuzzer.modification.AddToggleEncrytionActionModification;
import tlsattacker.fuzzer.modification.DuplicateMessageModification;
import tlsattacker.fuzzer.modification.ModificationType;
import tlsattacker.fuzzer.modification.ModifyFieldModification;
import tlsattacker.fuzzer.modification.RemoveMessageModification;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableListHolder;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.constants.NameType;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.ModificationException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionMessage;
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
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ToggleEncryptionAction;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import de.rub.nds.tlsattacker.util.ReflectionHelper;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;
import tlsattacker.fuzzer.certificate.ClientCertificateStructure;

/**
 * A helper class which implements useful methods to modify a TestVector on a
 * higher level.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzingHelper {

    private Random random;

    /**
     * Chooses a random modifiableVariableField from a List of
     * modifiableVariableFields
     * 
     * @param fields
     *            A list of Fields to pick from
     * @return A Random field
     */
    public ModifiableVariableField pickRandomField(List<ModifiableVariableField> fields) {

        int fieldNumber = random.nextInt(fields.size());
        return fields.get(fieldNumber);
    }

    /**
     * Returns a list of all ModifiableVariableHolders from the WorkflowTrace
     * that we send
     * 
     * @param trace
     *            Trace to search in
     * @return A list of all ModifieableVariableHolders
     */
    public List<ModifiableVariableHolder> getModifiableVariableHolders(WorkflowTrace trace) {
        List<ProtocolMessage> protocolMessages = trace.getAllConfiguredSendMessages();
        List<ModifiableVariableHolder> result = new LinkedList<>();
        for (ProtocolMessage pm : protocolMessages) {
            result.addAll(pm.getAllModifiableVariableHolders());
        }
        return result;
    }

    /**
     * Tries to find all ModifieableVariableFields in an Object
     * 
     * @param object
     *            Object to search in
     * @return List of all ModifieableVariableFields in an object
     */
    public List<ModifiableVariableField> getAllModifiableVariableFieldsRecursively(Object object) {
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
     *            Holder of the Field
     * @param field
     *            Field to modify
     * @return The ModificationObject
     */
    public ModifyFieldModification executeModifiableVariableModification(ModifiableVariableHolder object, Field field) {
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
     *            WorkflowTrace to which the Record should be added
     * @return The ModificationObject
     */
    public AddRecordModification addRecordAtRandom(WorkflowTrace trace) {
        List<ProtocolMessage> protocolMessages = trace.getAllConfiguredSendMessages();
        for (int i = 0; i < protocolMessages.size(); i++) {
            int randomPM = random.nextInt(protocolMessages.size());
            ProtocolMessage pm = protocolMessages.get(randomPM);
            Record r = new Record();
            if (random.nextInt(100) < 2) {
                r.setMaxRecordLengthConfig(random.nextInt(500000));
            } else {
                r.setMaxRecordLengthConfig(random.nextInt(50));
            }
            pm.addRecord(r);
            return new AddRecordModification(pm);

        }
        return null;
    }

    /**
     * Removes a random Message from a SendAction
     * 
     * @param tempTrace
     *            The WorkflowTrace to modify
     * @return The ModificationObject
     */
    public RemoveMessageModification removeRandomMessage(WorkflowTrace tempTrace) {
        SendAction action = getRandomSendAction(tempTrace);
        if (action.getConfiguredMessages().size() <= 1) {
            // We dont remove the last message from a flight
            return null;
        }
        int index = random.nextInt(action.getConfiguredMessages().size());
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
     *            The WorkflowTrace to modify
     * @return The ModificationObject
     */
    public AddMessageFlightModification addMessageFlight(WorkflowTrace tempTrace) {
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
     *            The WorkflowTrace to modify
     * @return The ModificationObject
     */
    public AddMessageModification addRandomMessage(WorkflowTrace tempTrace) {
        SendAction action = getRandomSendAction(tempTrace);
        if (action == null) {
            return null;
        } else {
            ProtocolMessage message = generateRandomMessage();
            action.getConfiguredMessages().add(message);
            return new AddMessageModification(message, action);
        }
    }

    /**
     * Chooses a random SendAction from the WorkflowTrace
     * 
     * @param tempTrace
     *            WorkflowTrace to choose from
     * @return Random SendAction from the WorkflowTrace
     */
    private SendAction getRandomSendAction(WorkflowTrace tempTrace) {
        List<SendAction> sendActions = tempTrace.getSendActions();
        if (sendActions.isEmpty()) {
            return null;
        }
        return sendActions.get(random.nextInt(sendActions.size()));
    }

    /**
     * Adds a random action which changes something in the TLSContext to the
     * WorkflowTrace
     * 
     * @param tempTrace
     *            WorkflowTrace to modify
     * @param mutator
     *            CertificateMutator to use
     * @return The ModificationObject
     */
    public AddContextActionModification addContextAction(WorkflowTrace tempTrace, CertificateMutator mutator) {
        AddContextActionModification modification = null;
        TLSAction action = null;
        ModificationType type = null;
        int position = random.nextInt(tempTrace.getTLSActions().size() + 1);
        switch (random.nextInt(9)) {
            case 0:
                type = ModificationType.ADD_CHANGE_CIPHERSUITE_ACTION;
                action = new ChangeCipherSuiteAction(CipherSuite.getRandom());
                break;
            case 1:
                type = ModificationType.ADD_CHANGE_CLIENT_CERTIFICATE_ACTION;
                ClientCertificateStructure clientCert = mutator.getClientCertificateStructure();
                String alias = clientCert.getAlias();
                String password = clientCert.getPassword();
                java.security.cert.Certificate sunCert = null;
                KeyStore ks = null;
                try {
                    ks = KeystoreHandler.loadKeyStore(clientCert.getJKSfile().getAbsolutePath(), password);
                    sunCert = ks.getCertificate(alias);
                    if (alias == null || sunCert == null) {
                        return null;
                    }
                    byte[] certBytes = sunCert.getEncoded();
                    ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
                    org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
                            .getInstance(asn1Cert);

                    org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
                    certs[0] = cert;
                    Certificate tlsCerts = new Certificate(certs);

                    X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));
                    action = new ChangeClientCertificateAction(cert, x509CertObject);
                } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException E) {
                    return null;
                }
                break;
            case 2:
                type = ModificationType.ADD_CHANGE_CLIENT_RANDOM_ACTION;
                byte[] newBytes = new byte[random.nextInt(1024)];
                random.nextBytes(newBytes);
                action = new ChangeClientRandomAction(newBytes);
                break;
            case 3:
                type = ModificationType.ADD_CHANGE_COMPRESSION_ACTION;
                CompressionMethod method = CompressionMethod.getRandom();
                action = new ChangeCompressionAction(method);
                break;
            case 4:
                type = ModificationType.ADD_CHANGE_MASTER_SECRET_ACTION;
                newBytes = new byte[random.nextInt(1024)];
                random.nextBytes(newBytes);
                action = new ChangeMasterSecretAction(newBytes);
                break;
            case 5:
                type = ModificationType.ADD_CHANGE_PREMASTER_SECRET_ACTION;
                newBytes = new byte[random.nextInt(1024)];
                random.nextBytes(newBytes);
                action = new ChangePreMasterSecretAction(newBytes);
                break;
            case 6:
                type = ModificationType.ADD_CHANGE_PROTOCOL_VERSION_ACTION;
                ProtocolVersion verion = ProtocolVersion.getRandom();
                action = new ChangeProtocolVersionAction(verion);
                break;
            case 7:
                type = ModificationType.ADD_CHANGE_SERVER_CERTIFICATE_ACTION;
                ClientCertificateStructure serverCert = mutator.getClientCertificateStructure();// TODO
                alias = serverCert.getAlias();
                password = serverCert.getPassword();
                sunCert = null;
                ks = null;
                try {
                    ks = KeystoreHandler.loadKeyStore(serverCert.getJKSfile().getAbsolutePath(), password);
                    sunCert = ks.getCertificate(alias);
                    if (alias == null || sunCert == null) {
                        return null;
                    }
                    byte[] certBytes = sunCert.getEncoded();
                    ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
                    org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
                            .getInstance(asn1Cert);

                    org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
                    certs[0] = cert;
                    Certificate tlsCerts = new Certificate(certs);

                    X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));
                    action = new ChangeServerCertificateAction(cert, x509CertObject);
                    break;
                } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
                    return null;
                }
            case 8:
                type = ModificationType.ADD_CHANGE_SERVER_RANDOM_ACTION;
                newBytes = new byte[random.nextInt(1024)];
                random.nextBytes(newBytes);
                action = new ChangeServerRandomAction(newBytes);
                break;
        }
        if (action != null) {
            tempTrace.add(position, action);
            modification = new AddContextActionModification(type, action);
        }
        return modification;
    }

    /**
     * Generates a new RandomMessage
     * 
     * @return A newly generated ProtocolMessage
     */
    public ProtocolMessage generateRandomMessage() {
        ProtocolMessage message = null;
        do {

            switch (random.nextInt(18)) {
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
                    int limit = random.nextInt(0xFF);
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
     * Adds and extension to a random ClientHello or DTLSClientHello message
     * 
     * @param trace
     *            WorkflowTrace to modify
     * @return The ModificationObject
     */
    public AddExtensionModification addExtensionMessage(WorkflowTrace trace) {
        ExtensionMessage message = generateRandomExtensionMessage();
        if (message != null) {
            List<ProtocolMessage> protocolMessages = trace.getAllConfiguredSendMessages();
            Collections.shuffle(protocolMessages);
            for (ProtocolMessage pm : protocolMessages) {
                if (pm instanceof ClientHelloMessage) {
                    ((ClientHelloMessage) pm).addExtension(message);
                    return new AddExtensionModification(message);
                }

            }
        }
        return null;
    }

    /**
     * Generates a random ExtensionMessage
     * 
     * @return Newly generated random ExtensionMessage
     */
    public ExtensionMessage generateRandomExtensionMessage() {
        ExtensionMessage message = null;
        switch (random.nextInt(6)) {
            case 0:
                EllipticCurvesExtensionMessage ecc = new EllipticCurvesExtensionMessage();
                List<NamedCurve> namedCurveList = new LinkedList<>();
                for (int i = 0; i < random.nextInt(100); i++)// TODO Config
                {
                    namedCurveList.add(NamedCurve.getRandom());
                }
                ecc.setSupportedCurvesConfig(namedCurveList);
                message = ecc;
                break;
            case 1:
                ECPointFormatExtensionMessage pfc = new ECPointFormatExtensionMessage();
                List<ECPointFormat> formatList = new LinkedList<>();
                for (int i = 0; i < random.nextInt(100); i++)// TODO Config
                {
                    formatList.add(ECPointFormat.getRandom());
                }
                pfc.setPointFormatsConfig(formatList);
                message = pfc;
                break;
            case 2:
                HeartbeatExtensionMessage hem = new HeartbeatExtensionMessage();
                hem.setHeartbeatModeConfig(HeartbeatMode.getRandom());
                message = hem;
                break;
            case 3:
                MaxFragmentLengthExtensionMessage mle = new MaxFragmentLengthExtensionMessage();
                mle.setMaxFragmentLengthConfig(MaxFragmentLength.getRandom());
                message = mle;
                break;
            case 4:
                ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
                sni.setNameTypeConfig(NameType.HOST_NAME);
                sni.setServerNameConfig("127.0.0.1");// TODO
                message = sni;
                break;
            case 5:
                SignatureAndHashAlgorithmsExtensionMessage sae = new SignatureAndHashAlgorithmsExtensionMessage();
                List<SignatureAndHashAlgorithm> signatureHashList = new LinkedList<>();
                for (int i = 0; i < random.nextInt(100); i++)// TODO Config
                {
                    signatureHashList.add(SignatureAndHashAlgorithm.getRandom());
                }
                sae.setSignatureAndHashAlgorithmsConfig(signatureHashList);
                message = sae;
                break;
        }
        return message;
    }

    /**
     * Duplicates a random ProtocolMessage and and adds it to a random position
     * in the Action
     * 
     * @param trace
     *            WorkflowTrace to modify
     * @return The ModificationObject
     */
    public DuplicateMessageModification duplicateRandomProtocolMessage(WorkflowTrace trace) {
        ProtocolMessage message = null;
        List<ProtocolMessage> protocolMessages = trace.getAllConfiguredSendMessages();
        if (protocolMessages.size() > 0) {
            message = (ProtocolMessage) UnoptimizedDeepCopy.copy(protocolMessages.get(random.nextInt(protocolMessages
                    .size())));
        } else {
            return null;
        }
        SendAction action = getRandomSendAction(trace);
        int insertPosition = random.nextInt(action.getConfiguredMessages().size() + 1);

        action.getConfiguredMessages().add(insertPosition, message);
        return new DuplicateMessageModification(message, action, insertPosition);
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance.
     * 
     * @param object
     *            Object to search in
     * @return List of all ModifieableVariableListHolders
     */
    public List<ModifiableVariableListHolder> getAllModifiableVariableHoldersRecursively(Object object) {
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

    /**
     * Adds a ToggleEncryptionAction to a WorkflowTrace
     * 
     * @param trace
     *            WorkflowTrace to modify
     * @return The ModificationObject
     */
    public AddToggleEncrytionActionModification addToggleEncrytionActionModification(WorkflowTrace trace) {
        TLSAction newAction = new ToggleEncryptionAction();
        List<TLSAction> actionList = trace.getTLSActions();
        int positon = random.nextInt(actionList.size() + 1);
        actionList.add(positon, newAction);
        return new AddToggleEncrytionActionModification(positon);
    }

    public FuzzingHelper() {
        random = new Random();
    }

    public Random getRandom() {
        return random;
    }

    public void setRandom(Random random) {
        if (random == null) {
            throw new IllegalArgumentException("Cannot set Random to null");
        }
        this.random = random;
    }

    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(FuzzingHelper.class
            .getName());
}
