/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.protocol.exception.ObjectCreationException;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

public class MessageFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static HandshakeMessage generateHandshakeMessage(
            HandshakeMessageType type, TlsContext tlsContext) {
        return switch (type) {
            case CERTIFICATE -> new CertificateMessage();
            case CERTIFICATE_REQUEST -> new CertificateRequestMessage();
            case CERTIFICATE_STATUS -> new CertificateStatusMessage();
            case CERTIFICATE_VERIFY -> new CertificateVerifyMessage();
            case CLIENT_HELLO -> new ClientHelloMessage();
            case CLIENT_KEY_EXCHANGE -> getClientKeyExchangeMessage(tlsContext);
            case ENCRYPTED_EXTENSIONS -> new EncryptedExtensionsMessage();
            case END_OF_EARLY_DATA -> new EndOfEarlyDataMessage();
            case FINISHED -> new FinishedMessage();
            case HELLO_REQUEST -> new HelloRequestMessage();
            case HELLO_VERIFY_REQUEST -> new HelloVerifyRequestMessage();
            case KEY_UPDATE -> new KeyUpdateMessage();
            case MESSAGE_HASH -> {
                LOGGER.warn(
                        "Received MessageHash HandshakeMessageType - not implemented yet. Treating as UnknownHandshakeMessage");
                yield new UnknownHandshakeMessage();
            }
            case NEW_SESSION_TICKET -> new NewSessionTicketMessage();
            case SERVER_HELLO -> new ServerHelloMessage();
            case SERVER_HELLO_DONE -> new ServerHelloDoneMessage();
            case SERVER_KEY_EXCHANGE -> getServerKeyExchangeMessage(tlsContext);
            case UNKNOWN -> new UnknownHandshakeMessage();
            case SUPPLEMENTAL_DATA -> new SupplementalDataMessage();
            default -> throw new RuntimeException("Unexpected HandshakeMessage Type " + type);
        };
    }

    private static ServerKeyExchangeMessage getServerKeyExchangeMessage(TlsContext tlsContext) {
        CipherSuite cs = tlsContext.getChooser().getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = cs.getKeyExchangeAlgorithm();
        return switch (algorithm) {
            case null ->
                    throw new UnsupportedOperationException(
                            "CipherSuite '" + cs + "'does not have a KeyExchangeAlgorithm");
            case ECDHE_ECDSA, ECDH_ECDSA, ECDH_RSA, ECDHE_RSA, ECDH_ANON ->
                    new ECDHEServerKeyExchangeMessage();
            case DHE_DSS, DHE_RSA, DH_ANON, DH_DSS, DH_RSA -> new DHEServerKeyExchangeMessage();
            case RSA, RSA_EXPORT -> new RSAServerKeyExchangeMessage();
            case PSK -> new PskServerKeyExchangeMessage();
            case DHE_PSK -> new PskDheServerKeyExchangeMessage();
            case ECDHE_PSK -> new PskEcDheServerKeyExchangeMessage();
            case SRP_SHA_DSS, SRP_SHA_RSA, SRP_SHA -> new SrpServerKeyExchangeMessage();
            case ECCPWD -> new PWDServerKeyExchangeMessage();
            default ->
                    throw new UnsupportedOperationException(
                            "Algorithm " + algorithm + " NOT supported yet.");
        };
    }

    private static ClientKeyExchangeMessage getClientKeyExchangeMessage(TlsContext tlsContext) {
        CipherSuite cs = tlsContext.getChooser().getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = cs.getKeyExchangeAlgorithm();
        return switch (algorithm) {
            case null ->
                    throw new UnsupportedOperationException(
                            "CipherSuite '" + cs + "'does not have a KeyExchangeAlgorithm");
            case RSA -> new RSAClientKeyExchangeMessage();
            case ECDHE_ECDSA, ECDH_ECDSA, ECDH_RSA, ECDHE_RSA -> new ECDHClientKeyExchangeMessage();
            case DHE_DSS, DHE_RSA, DH_ANON, DH_DSS, DH_RSA -> new DHClientKeyExchangeMessage();
            case DHE_PSK -> new PskDhClientKeyExchangeMessage();
            case ECDHE_PSK -> new PskEcDhClientKeyExchangeMessage();
            case RSA_PSK -> new PskRsaClientKeyExchangeMessage();
            case PSK -> new PskClientKeyExchangeMessage();
            case SRP_SHA_DSS, SRP_SHA_RSA, SRP_SHA -> new SrpClientKeyExchangeMessage();
            case VKO_GOST01, VKO_GOST12 -> new GOSTClientKeyExchangeMessage();
            case ECCPWD -> new PWDClientKeyExchangeMessage();
            default ->
                    throw new UnsupportedOperationException(
                            "Algorithm " + algorithm + " NOT supported yet.");
        };
    }

    public static List<ProtocolMessage> generateProtocolMessages() {
        List<ProtocolMessage> protocolMessageList = new LinkedList<>();
        Set<Class<? extends ProtocolMessage>> classes = getAllNonAbstractProtocolMessageClasses();
        for (Class<? extends ProtocolMessage> someClass : classes) {
            protocolMessageList.add(createProtocolMessage(someClass));
        }
        return protocolMessageList;
    }

    public static List<ExtensionMessage> generateExtensionMessages() {
        List<ExtensionMessage> extensionMessageList = new LinkedList<>();
        Set<Class<? extends ExtensionMessage>> classes = getAllNonAbstractExtensionClasses();
        for (Class<? extends ExtensionMessage> someClass : classes) {
            extensionMessageList.add(createExtensionMessage(someClass));
        }
        return extensionMessageList;
    }

    private static ExtensionMessage createExtensionMessage(
            Class<? extends ExtensionMessage> extensionClass) {
        if (Modifier.isAbstract(extensionClass.getModifiers())) {
            throw new IllegalArgumentException("Provided class is abstract");
        }
        try {
            return extensionClass.getConstructor().newInstance();
        } catch (NoSuchMethodException
                | InstantiationException
                | IllegalAccessException
                | IllegalArgumentException
                | InvocationTargetException ex) {
            throw new ObjectCreationException("Could not create Extension", ex);
        }
    }

    private static ProtocolMessage createProtocolMessage(
            Class<? extends ProtocolMessage> protocolMessageClass) {
        if (Modifier.isAbstract(protocolMessageClass.getModifiers())) {
            throw new IllegalArgumentException("Provided class is abstract");
        }
        try {
            return protocolMessageClass.getConstructor().newInstance();
        } catch (NoSuchMethodException
                | InstantiationException
                | IllegalAccessException
                | IllegalArgumentException
                | InvocationTargetException ex) {
            throw new ObjectCreationException("Could not create ProtocolMessage", ex);
        }
    }

    private static Set<Class<? extends ExtensionMessage>> getAllNonAbstractExtensionClasses() {
        Reflections reflections =
                new Reflections("de.rub.nds.tlsattacker.core.protocol.message.extension");
        Set<Class<? extends ExtensionMessage>> classes =
                reflections.getSubTypesOf(ExtensionMessage.class);
        Set<Class<? extends ExtensionMessage>> filteredClassSet = new HashSet<>();
        for (Class<? extends ExtensionMessage> someClass : classes) {
            if (!Modifier.isAbstract(someClass.getModifiers())) {
                filteredClassSet.add(someClass);
            }
        }
        return filteredClassSet;
    }

    private static Set<Class<? extends ProtocolMessage>> getAllNonAbstractProtocolMessageClasses() {
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.protocol.message");
        Set<Class<? extends ProtocolMessage>> classes =
                reflections.getSubTypesOf(ProtocolMessage.class);
        Set<Class<? extends ProtocolMessage>> filteredClassSet = new HashSet<>();
        for (Class<? extends ProtocolMessage> someClass : classes) {
            if (!Modifier.isAbstract(someClass.getModifiers())) {
                filteredClassSet.add(someClass);
            }
        }
        return filteredClassSet;
    }

    public static ProtocolMessage generateRandomProtocolMessage(Random r) {
        List<ProtocolMessage> generateProtocolMessages = generateProtocolMessages();
        return generateProtocolMessages.get(r.nextInt(generateProtocolMessages.size()));
    }

    public static ExtensionMessage generateRandomExtension(Random r) {
        List<ExtensionMessage> extensionMessages = generateExtensionMessages();
        return extensionMessages.get(r.nextInt(extensionMessages.size()));
    }

    private MessageFactory() {}
}
