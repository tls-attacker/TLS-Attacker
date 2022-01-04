/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.security.Security;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.reflections.Reflections;

public class CyclicParserSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testParserSerializerPairs() {
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.protocol.parser");
        Set<Class<? extends ProtocolMessageParser>> parserClasses =
            reflections.getSubTypesOf(ProtocolMessageParser.class);
        CONSOLE.info("ProtocolMessageParser classes:" + parserClasses.size());
        ProtocolMessageParser<? extends ProtocolMessage> parser = null;
        ProtocolMessagePreparator<? extends ProtocolMessage> preparator = null;
        ProtocolMessage message = null;
        Config config = null;
        ProtocolMessageSerializer<? extends ProtocolMessage> serializer = null;
        for (Class<? extends ProtocolMessageParser> someParserClass : parserClasses) {
            if (Modifier.isAbstract(someParserClass.getModifiers())) {
                CONSOLE.info("Skipping:" + someParserClass.getSimpleName());
                continue;
            }
            String testName = someParserClass.getSimpleName().replace("Parser", "");

            Class<? extends ProtocolMessagePreparator> preparatorClass = null;
            try {
                preparatorClass = getPreparator(testName);
                if (Modifier.isAbstract(preparatorClass.getModifiers())) {
                    CONSOLE.info("Skipping:" + preparatorClass.getSimpleName());
                    continue;
                }
            } catch (ClassNotFoundException e) {
                LOGGER.warn(e);
            }

            CONSOLE.info("Testing:" + testName);
            for (ProtocolVersion version : ProtocolVersion.values()) {
                if (version.isDTLS()) {
                    continue;
                }
                // Trying to find equivalent preparator, message and serializer
                try {
                    Class<? extends ProtocolMessage> protocolMessageClass = getProtocolMessage(testName);
                    if (protocolMessageClass == DtlsHandshakeMessageFragment.class) {
                        continue;
                    }
                    try {
                        Constructor tempConstructor = getMessageConstructor(protocolMessageClass);
                        if (tempConstructor != null) {
                            message = (ProtocolMessage) getMessageConstructor(protocolMessageClass)
                                .newInstance(Config.createConfig());
                        } else {
                            fail("Could not find Constructor for " + testName);
                        }
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        fail("Could not create message instance for " + testName);
                    }

                    try {
                        TlsContext context = new TlsContext();
                        context.setSelectedProtocolVersion(version);
                        context.getConfig().setHighestProtocolVersion(version);
                        context.getConfig().setDefaultHighestClientProtocolVersion(version);
                        config = context.getConfig();
                        preparator = (ProtocolMessagePreparator) getConstructor(preparatorClass, 2)
                            .newInstance(context.getChooser(), message);
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        fail("Could not create preparator instance for " + testName);
                    }
                    // Preparing message
                    try {
                        preparator.prepare();
                    } catch (UnsupportedOperationException E) {
                        CONSOLE.info("Preparator for " + testName + " is unsupported yet");
                        continue;
                    }
                    Class<? extends ProtocolMessageSerializer> serializerClass = getSerializer(testName);
                    try {
                        serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 2).newInstance(message,
                            version);
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        fail("Could not create serializer instance for " + testName);
                    }
                    byte[] serializedMessage = serializer.serialize();
                    try {
                        parser = (ProtocolMessageParser) getConstructor(someParserClass, 4).newInstance(0,
                            serializedMessage, version, config);
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        fail("Could not create parser instance for " + testName);
                    }
                    try {
                        message = parser.parse();
                    } catch (UnsupportedOperationException E) {
                        CONSOLE.info("##########" + testName + " parsing is unsupported!");
                        continue;
                    }
                    try {
                        serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 2).newInstance(message,
                            version);
                    } catch (InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                        fail("Could not create serializer instance for " + testName);
                    }
                    Assert.assertArrayEquals(testName + " failed", serializedMessage, serializer.serialize());
                    CONSOLE.info("......." + testName + " - " + version.name() + " works as expected!");
                } catch (Exception ex) {
                    LOGGER.error(ex);
                    fail("Could not execute " + testName + " - " + version.name());
                }
            }
        }
    }

    @Category(IntegrationTests.class)
    @Test
    public void testParserSerializerDefaultConstructorPairs() {
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.protocol.parser");
        Set<Class<? extends ProtocolMessageParser>> parserClasses =
            reflections.getSubTypesOf(ProtocolMessageParser.class);
        CONSOLE.info("ProtocolMessageParser classes:" + parserClasses.size());
        ProtocolMessageParser<? extends ProtocolMessage> parser = null;
        ProtocolMessagePreparator<? extends ProtocolMessage> preparator = null;
        ProtocolMessage message = null;
        ProtocolMessageSerializer<? extends ProtocolMessage> serializer = null;
        for (Class<? extends ProtocolMessageParser> someParserClass : parserClasses) {
            if (Modifier.isAbstract(someParserClass.getModifiers())) {
                CONSOLE.info("Skipping:" + someParserClass.getSimpleName());
                continue;
            }
            String testName = someParserClass.getSimpleName().replace("Parser", "");
            CONSOLE.info("Testing:" + testName);

            Class<? extends ProtocolMessagePreparator> preparatorClass = null;
            try {
                preparatorClass = getPreparator(testName);
                if (Modifier.isAbstract(preparatorClass.getModifiers())) {
                    CONSOLE.info("Skipping:" + preparatorClass.getSimpleName());
                    continue;
                }
            } catch (ClassNotFoundException e) {
                LOGGER.warn(e);
            }

            for (ProtocolVersion version : ProtocolVersion.values()) {
                if (version.isDTLS()) {
                    continue;
                }

                TlsContext context = new TlsContext();
                context.setSelectedProtocolVersion(version);
                context.getConfig().setHighestProtocolVersion(version);
                context.getConfig().setDefaultHighestClientProtocolVersion(version);

                // Trying to find equivalent preparator, message and serializer
                try {
                    Class<? extends ProtocolMessage> protocolMessageClass = getProtocolMessage(testName);
                    try {
                        Constructor tempConstructor = getDefaultMessageConstructor(protocolMessageClass);
                        if (tempConstructor != null) {
                            message =
                                (ProtocolMessage) getDefaultMessageConstructor(protocolMessageClass).newInstance();
                        } else {
                            fail("Could not find Constructor for " + testName);
                        }
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        fail("Could not create message instance for " + testName);
                    }

                    try {
                        preparator = (ProtocolMessagePreparator) getConstructor(preparatorClass, 2)
                            .newInstance(context.getChooser(), message);
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        ex.printStackTrace();
                        fail("Could not create preparator instance for " + testName);
                    }
                    // Preparing message
                    try {
                        preparator.prepare();
                    } catch (UnsupportedOperationException E) {
                        CONSOLE.info("Preparator for " + testName + " is unsupported yet");
                        continue;
                    }
                    Class<? extends ProtocolMessageSerializer> serializerClass = getSerializer(testName);
                    try {
                        serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 2).newInstance(message,
                            version);
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        fail("Could not create serializer instance for " + testName);
                    }
                    byte[] serializedMessage = serializer.serialize();
                    try {
                        parser = (ProtocolMessageParser) getConstructor(someParserClass, 4).newInstance(0,
                            serializedMessage, version, context.getConfig());
                    } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                        fail("Could not create parser instance for " + testName);
                    }
                    try {
                        message = parser.parse();
                    } catch (UnsupportedOperationException E) {
                        CONSOLE.info("##########" + testName + " parsing is unsupported!");
                        continue;
                    }
                    try {
                        serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 2).newInstance(message,
                            version);
                    } catch (InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                        fail("Could not create serializer instance for " + testName);
                    }
                    Assert.assertArrayEquals(testName + " failed", serializedMessage, serializer.serialize());
                    CONSOLE.info("......." + testName + " - " + version.name() + " works as expected!");
                } catch (ClassNotFoundException ex) {
                    fail("Could not execute " + testName + " - " + version.name());
                }
            }
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

    private Constructor getMessageConstructor(Class someClass) {
        for (Constructor c : someClass.getConstructors()) {
            if (c.getParameterCount() == 1) {
                if (c.getParameterTypes()[0].equals(Config.class)) {
                    return c;
                }
            }
        }
        LOGGER.warn("Could not find Constructor: " + someClass.getSimpleName());
        return null;
    }

    private Constructor getDefaultMessageConstructor(Class someClass) {
        for (Constructor c : someClass.getDeclaredConstructors()) {
            if (c.getParameterCount() == 0) {
                return c;
            }
        }
        LOGGER.warn("Could not find Constructor: " + someClass.getSimpleName());
        return null;
    }

    private Constructor getConstructor(Class someClass, int numberOfArguments) {
        for (Constructor c : someClass.getConstructors()) {
            if (c.getParameterCount() == numberOfArguments) {
                return c;
            }
        }
        LOGGER.warn("Could not find Constructor: " + someClass.getSimpleName());
        return null;
    }
}
