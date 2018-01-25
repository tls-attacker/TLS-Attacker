/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.reflections.Reflections;

public class CyclicParserSerializerTest {

    protected static final Logger LOGGER = LogManager.getLogger(CyclicParserSerializerTest.class.getName());

    @Test
    public void testParserSerializerPairs() {
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.protocol.parser");
        Set<Class<? extends ProtocolMessageParser>> parserClasses = reflections
                .getSubTypesOf(ProtocolMessageParser.class);
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "ProtocolMessageParser classes:" + parserClasses.size());
        ProtocolMessageParser parser = null;
        ProtocolMessagePreparator preparator = null;
        ProtocolMessage message = null;
        ProtocolMessageSerializer serializer = null;
        for (Class<? extends ProtocolMessageParser> someParserClass : parserClasses) {
            if (Modifier.isAbstract(someParserClass.getModifiers())) {
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Skipping:" + someParserClass.getSimpleName());
                continue;
            }
            String testName = someParserClass.getSimpleName().replace("Parser", "");
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Testing:" + testName);
            // Trying to find equivalent preparator, message and serializer
            try {
                Class<? extends ProtocolMessage> protocolMessageClass = getProtocolMessage(testName);
                try {
                    message = (ProtocolMessage) getConstructor(protocolMessageClass, 1).newInstance(
                            Config.createConfig());
                } catch (SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                    ex.printStackTrace();
                    fail("Could not create message instance for " + testName);
                }
                Class<? extends ProtocolMessagePreparator> preparatorClass = getPreparator(testName);
                try {
                    preparator = (ProtocolMessagePreparator) getConstructor(preparatorClass, 2).newInstance(
                            new TlsContext().getChooser(), message);
                } catch (SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                    ex.printStackTrace();
                    fail("Could not create preparator instance for " + testName);
                }
                // Preparing message
                try {
                    preparator.prepare();
                } catch (UnsupportedOperationException E) {
                    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Preparator for " + testName + " is unsupported yet");
                    continue;
                }
                Class<? extends ProtocolMessageSerializer> serializerClass = getSerializer(testName);
                try {
                    serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 2).newInstance(message,
                            ProtocolVersion.TLS12);
                } catch (SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                    ex.printStackTrace();
                    fail("Could not create serializer instance for " + testName);
                }
                byte[] serializedMessage = serializer.serialize();
                try {
                    parser = (ProtocolMessageParser) getConstructor(someParserClass, 3).newInstance(0,
                            serializedMessage, ProtocolVersion.TLS12);
                } catch (SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                    ex.printStackTrace();
                    fail("Could not create parser instance for " + testName);
                }
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "......." + testName + " works as expected!");
            } catch (ClassNotFoundException ex) {
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Could not execute " + testName, ex);
                ex.printStackTrace();
            }
            /*
             * try { parser = someParserClass.getConstructor().newInstance(); }
             * catch (NoSuchMethodException | SecurityException |
             * InstantiationException | IllegalAccessException |
             * IllegalArgumentException | InvocationTargetException ex) {
             * LOGGER.log(LogLevel.CONSOLE_OUTPUT,
             * "Could not create instance for:" + someParserClass.getName()); }
             */
        }
    }

    private Class<? extends ProtocolMessage> getProtocolMessage(String testName) throws ClassNotFoundException {
        String messageName = "de.rub.nds.tlsattacker.core.protocol.message." + testName;
        try {
            return (Class<? extends ProtocolMessage>) Class.forName(messageName);
        } catch (ClassNotFoundException E) {
            try {
                return (Class<? extends ProtocolMessage>) Class.forName(messageName + "Message");
            } catch (ClassNotFoundException ex) {
                throw new ClassNotFoundException("Could not find Message for " + testName);
            }
        }

    }

    private Class<? extends ProtocolMessagePreparator> getPreparator(String testName) throws ClassNotFoundException {
        String preparatorName = "de.rub.nds.tlsattacker.core.protocol.preparator." + testName + "Preparator";
        try {
            return (Class<? extends ProtocolMessagePreparator>) Class.forName(preparatorName);
        } catch (ClassNotFoundException E) {
            try {
                preparatorName = "de.rub.nds.tlsattacker.core.protocol.preparator." + testName + "MessagePreparator";
                return (Class<? extends ProtocolMessagePreparator>) Class.forName(preparatorName);
            } catch (ClassNotFoundException ex) {
                throw new ClassNotFoundException("Could not find Preparator for " + testName);
            }
        }
    }

    private Class<? extends ProtocolMessageSerializer> getSerializer(String testName) throws ClassNotFoundException {
        String serializerName = "de.rub.nds.tlsattacker.core.protocol.serializer." + testName + "Serializer";
        try {
            return (Class<? extends ProtocolMessageSerializer>) Class.forName(serializerName);
        } catch (ClassNotFoundException E) {
            try {
                return (Class<? extends ProtocolMessageSerializer>) Class.forName(serializerName + "MessageSerializer");
            } catch (ClassNotFoundException ex) {
                throw new ClassNotFoundException("Could not find Serializer for " + testName);
            }
        }
    }

    private Constructor getConstructor(Class someClass, int numberOfArguemnts) {
        for (Constructor c : someClass.getConstructors()) {
            if (c.getParameterCount() == numberOfArguemnts) {
                return c;
            }
        }
        return null;
    }
}
