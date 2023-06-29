/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ObjectCreationException;
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
        switch (type) {
            case CERTIFICATE:
                return new CertificateMessage();
            case CERTIFICATE_REQUEST:
                return new CertificateRequestMessage();
            case CERTIFICATE_STATUS:
                return new CertificateStatusMessage();
            case CERTIFICATE_VERIFY:
                return new CertificateVerifyMessage();
            case CLIENT_HELLO:
                return new ClientHelloMessage();
            case CLIENT_KEY_EXCHANGE:
                return getClientKeyExchangeMessage(tlsContext);
            case ENCRYPTED_EXTENSIONS:
                return new EncryptedExtensionsMessage();
            case END_OF_EARLY_DATA:
                return new EndOfEarlyDataMessage();
            case FINISHED:
                return new FinishedMessage();
            case HELLO_REQUEST:
                return new HelloRequestMessage();
            case HELLO_VERIFY_REQUEST:
                return new HelloVerifyRequestMessage();
            case KEY_UPDATE:
                return new KeyUpdateMessage();
            case MESSAGE_HASH:
                LOGGER.warn(
                        "Received MessageHash HandshakeMessageType - not implemented yet. Treating as UnknownHandshakeMessage");
                return new UnknownHandshakeMessage();
            case NEW_SESSION_TICKET:
                return new NewSessionTicketMessage();
            case SERVER_HELLO:
                return new ServerHelloMessage();
            case SERVER_HELLO_DONE:
                return new ServerHelloDoneMessage();
            case SERVER_KEY_EXCHANGE:
                return getServerKeyExchangeMessage(tlsContext);
            case UNKNOWN:
                return new UnknownHandshakeMessage();
            case SUPPLEMENTAL_DATA:
                return new SupplementalDataMessage();
            default:
                throw new RuntimeException("Unexpected HandshakeMessage Type " + type);
        }
    }

    private static ServerKeyExchangeMessage getServerKeyExchangeMessage(TlsContext tlsContext) {
        CipherSuite cs = tlsContext.getChooser().getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
        switch (algorithm) {
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECDH_RSA:
            case ECDHE_RSA:
            case ECDH_ANON:
                return new ECDHEServerKeyExchangeMessage();
            case DHE_DSS:
            case DHE_RSA:
            case DH_ANON:
            case DH_DSS:
            case DH_RSA:
                return new DHEServerKeyExchangeMessage();
            case PSK:
                return new PskServerKeyExchangeMessage();
            case DHE_PSK:
                return new PskDheServerKeyExchangeMessage();
            case ECDHE_PSK:
                return new PskEcDheServerKeyExchangeMessage();
            case SRP_SHA_DSS:
            case SRP_SHA_RSA:
            case SRP_SHA:
                return new SrpServerKeyExchangeMessage();
            case ECCPWD:
                return new PWDServerKeyExchangeMessage();
            default:
                throw new UnsupportedOperationException(
                        "Algorithm " + algorithm + " NOT supported yet.");
        }
    }

    private static ClientKeyExchangeMessage getClientKeyExchangeMessage(TlsContext tlsContext) {
        CipherSuite cs = tlsContext.getChooser().getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
        switch (algorithm) {
            case RSA:
                return new RSAClientKeyExchangeMessage();
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECDH_RSA:
            case ECDHE_RSA:
                return new ECDHClientKeyExchangeMessage();
            case DHE_DSS:
            case DHE_RSA:
            case DH_ANON:
            case DH_DSS:
            case DH_RSA:
                return new DHClientKeyExchangeMessage();
            case DHE_PSK:
                return new PskDhClientKeyExchangeMessage();
            case ECDHE_PSK:
                return new PskEcDhClientKeyExchangeMessage();
            case PSK_RSA:
                return new PskRsaClientKeyExchangeMessage();
            case PSK:
                return new PskClientKeyExchangeMessage();
            case SRP_SHA_DSS:
            case SRP_SHA_RSA:
            case SRP_SHA:
                return new SrpClientKeyExchangeMessage();
            case VKO_GOST01:
            case VKO_GOST12:
                return new GOSTClientKeyExchangeMessage();
            case ECCPWD:
                return new PWDClientKeyExchangeMessage();
            default:
                throw new UnsupportedOperationException(
                        "Algorithm " + algorithm + " NOT supported yet.");
        }
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
