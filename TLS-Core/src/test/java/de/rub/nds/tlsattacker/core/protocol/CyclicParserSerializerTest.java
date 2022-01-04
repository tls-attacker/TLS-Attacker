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
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.reflections.Reflections;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.security.Security;
import java.util.Set;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.junit.Assert.fail;

public class CyclicParserSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }

    @Test
    @Category(IntegrationTests.class)
    public void testParserSerializerPairs() {
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.protocol.message");
        Set<Class<? extends ProtocolMessage>> messageClasses = reflections.getSubTypesOf(ProtocolMessage.class);
        CONSOLE.info("ProtocolMessageParser classes:" + messageClasses.size());
        ProtocolMessage message = null;
        Config config = null;
        for (Class<? extends ProtocolMessage> someMessageClass : messageClasses) {
            if (Modifier.isAbstract(someMessageClass.getModifiers())) {
                CONSOLE.info("Skipping:" + someMessageClass.getSimpleName());
                continue;
            }
            String testName = someMessageClass.getSimpleName().replace("Parser", "");

            CONSOLE.info("Testing:" + testName);
            for (ProtocolVersion version : ProtocolVersion.values()) {
                // Trying to find equivalent preparator, message and serializer

                if (someMessageClass == DtlsHandshakeMessageFragment.class) {
                    continue;
                }
                try {
                    Constructor tempConstructor = getMessageConstructor(someMessageClass);
                    if (tempConstructor != null) {
                        message = (ProtocolMessage) getMessageConstructor(someMessageClass)
                            .newInstance(Config.createConfig());
                    } else {
                        fail("Could not find Constructor for " + testName);
                    }
                } catch (SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException
                    | InvocationTargetException ex) {
                    fail("Could not create message instance for " + testName);
                }

                try {
                    TlsContext context = new TlsContext();
                    context.setSelectedProtocolVersion(version);
                    context.getConfig().setHighestProtocolVersion(version);
                    context.getConfig().setDefaultHighestClientProtocolVersion(version);
                    context.getConfig().setDefaultLastRecordProtocolVersion(version);

                    ProtocolMessagePreparator preparator = message.getPreparator(context);
                    preparator.prepare();
                    ProtocolMessageSerializer serializer = message.getSerializer(context);
                    byte[] serializedMessage = serializer.serializeProtocolMessageContent();
                    message =
                        (ProtocolMessage) getMessageConstructor(someMessageClass).newInstance(Config.createConfig());
                    ProtocolMessageParser parser =
                        message.getParser(context, new ByteArrayInputStream(serializedMessage));
                    parser.parse(message);
                    byte[] serializedMessage2 = message.getSerializer(context).serializeProtocolMessageContent();
                    Assert.assertArrayEquals(testName + " failed", serializedMessage, serializedMessage2);
                    CONSOLE.info("......." + testName + " - " + version.name() + " works as expected!");
                } catch (UnsupportedOperationException ex) {
                    CONSOLE.info("Unsupported! Skipping:" + testName);
                    continue;
                } catch (Exception ex) {
                    ex.printStackTrace();
                    fail("Could not execute " + testName + " - " + version.name());
                }
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
}
