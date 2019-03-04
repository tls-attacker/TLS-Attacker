/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.exceptions.ObjectCreationException;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

public class MessageFactory {

    private static final Logger LOGGER = LogManager.getLogger();

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

    private static ExtensionMessage createExtensionMessage(Class<? extends ExtensionMessage> extensionClass) {
        if (Modifier.isAbstract(extensionClass.getModifiers())) {
            throw new IllegalArgumentException("Provided class is abstract");
        }
        try {
            return extensionClass.getConstructor().newInstance();
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | IllegalArgumentException
                | InvocationTargetException ex) {
            throw new ObjectCreationException("Could not create Extension", ex);
        }
    }

    private static ProtocolMessage createProtocolMessage(Class<? extends ProtocolMessage> protocolMessageClass) {
        if (Modifier.isAbstract(protocolMessageClass.getModifiers())) {
            throw new IllegalArgumentException("Provided class is abstract");
        }
        try {
            return protocolMessageClass.getConstructor().newInstance();
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | IllegalArgumentException
                | InvocationTargetException ex) {
            throw new ObjectCreationException("Could not create ProtocolMessage", ex);
        }
    }

    private static Set<Class<? extends ExtensionMessage>> getAllNonAbstractExtensionClasses() {
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.protocol.message.extension");
        Set<Class<? extends ExtensionMessage>> classes = reflections.getSubTypesOf(ExtensionMessage.class);
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
        Set<Class<? extends ProtocolMessage>> classes = reflections.getSubTypesOf(ProtocolMessage.class);
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

    private MessageFactory() {
    }
}
