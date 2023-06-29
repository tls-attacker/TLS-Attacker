/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.unittest.helper.DefaultNormalizeFilter;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import jakarta.xml.bind.JAXB;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Convenience methods for common TlsAction tests. */
public class ActionTestUtils {

    /**
     * Verify that the given TlsAction can be marshaled to minimal output.
     *
     * <p>Same as {@link #marshalingEmptyActionYieldsMinimalOutput(Class, Logger)}, but sets the
     * logger automatically.
     *
     * <p>
     *
     * @param <T>
     * @param actionClass the Class to test
     * @see #marshalingEmptyActionYieldsMinimalOutput(Class, Logger)
     */
    public static <T extends TlsAction> void marshalingEmptyActionYieldsMinimalOutput(
            Class<T> actionClass) {
        marshalingEmptyActionYieldsMinimalOutput(actionClass, LogManager.getLogger(actionClass));
    }

    /**
     * Verify that the given TlsAction can be marshaled to minimal output.
     *
     * <p>Test has two purposes
     *
     * <ol>
     *   <li>Verify that the action class is known to the JAXB context
     *   <li>Verify that marshaling of an empty instance yields minimal output
     * </ol>
     *
     * <p>If this test fails and the output shows a "wrong" class name, i.e. TlsAction, check that a
     * proper @XmlElement() annotation for the class exists for the WorkflowTrace.tlsActions field.
     * You can be sure that it's missing if you see xmlns:xsi schema values in the output.
     *
     * <p>Calling this method is expensive, since it goes through the whole
     * normalize/filter/serialize procedure. <b>Should be invoked by tests in
     * Category(SlowTests.class) only</b>
     *
     * @param <T>
     * @param actionClass the Class to test
     * @param logger the logger to which messages are written to
     * @see #marshalingEmptyActionYieldsMinimalOutput(Class)
     */
    public static <T extends TlsAction> void marshalingEmptyActionYieldsMinimalOutput(
            Class<T> actionClass, Logger logger) {
        try {
            WorkflowTrace trace = new WorkflowTrace();
            T action = actionClass.getDeclaredConstructor().newInstance();
            trace.addTlsAction(action);
            String xmlName = action.getClass().getSimpleName();
            if (xmlName.endsWith("Action")) {
                xmlName = xmlName.substring(0, xmlName.length() - 6);
            } else {
                logger.warn(
                        "The action under test does not follow naming convention. "
                                + xmlName
                                + " does not end with string 'Action'");
            }
            String expected =
                    "<workflowTrace>"
                            + System.lineSeparator()
                            + "    <"
                            + xmlName
                            + ">"
                            + System.lineSeparator()
                            + "        <actionOptions/>"
                            + System.lineSeparator()
                            + "    </"
                            + xmlName
                            + ">"
                            + System.lineSeparator()
                            + "</workflowTrace>"
                            + System.lineSeparator();

            Config config = Config.createConfig();
            // We don't need to keep user settings. Skip for better performance.
            config.setFiltersKeepUserSettings(false);
            DefaultNormalizeFilter.normalizeAndFilter(trace, config);
            String actual = WorkflowTraceSerializer.write(trace);
            logger.info(actual);

            assertEquals(expected, actual);

        } catch (JAXBException
                | IOException
                | InstantiationException
                | IllegalAccessException
                | InvocationTargetException
                | NoSuchMethodException ex) {
            logger.error(ex.getLocalizedMessage(), ex);
            fail();
        }
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for empty action equals original action.
     *
     * <p>Same as {@link #marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(Class, Logger)}, but
     * sets the logger automatically.
     *
     * <p>
     *
     * @param <T>
     * @param actionClass the Class to test
     * @see #marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(Class, Logger)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(
            Class<T> actionClass) {
        marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(
                actionClass, LogManager.getLogger(actionClass));
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for empty action equals original action.
     *
     * <p>"Empty" action refers to a TlsAction instance initialized with empty constructor and
     * without any additional values set.
     *
     * <p>Calling this method is expensive. <b>Should be invoked by tests in
     * {@literal @}Category(SlowTests.class) only</b>
     *
     * <p>
     *
     * @param <T>
     * @param actionClass the Class to test
     * @param logger to which messages are written to
     * @see #marshalingEmptyActionYieldsMinimalOutput(Class)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(
            Class<T> actionClass, Logger logger) {
        try {
            T action = actionClass.getDeclaredConstructor().newInstance();
            StringWriter writer = new StringWriter();

            action.filter();
            JAXB.marshal(action, writer);
            TlsAction actual =
                    JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), actionClass);
            action.normalize();
            actual.normalize();

            assertEquals(action, actual);
        } catch (InstantiationException
                | IllegalAccessException
                | NoSuchMethodException
                | InvocationTargetException ex) {
            logger.error(ex.getLocalizedMessage(), ex);
            fail();
        }
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for non-empty action equals original action.
     *
     * <p>Same as {@link #marshalingAndUnmarshalingFilledObjectYieldsEqualObject(TlsAction,
     * Logger)}, but sets the logger automatically.
     *
     * <p>
     *
     * @param <T>
     * @param action an instance of the TlsAction class under test, filled with custom values
     * @see #marshalingAndUnmarshalingFilledObjectYieldsEqualObject(TlsAction, Logger)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingFilledObjectYieldsEqualObject(
            T action) {
        marshalingAndUnmarshalingFilledObjectYieldsEqualObject(
                action, LogManager.getLogger(action.getClass().getName()));
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for non-empty action equals original action.
     *
     * <p>"Non-empty" or "filled" action refers to a TlsAction instance which has some custom values
     * set.
     *
     * <p>Calling this method is expensive. <b>Should be invoked by tests in
     * Category(SlowTests.class) only</b>
     *
     * <p>
     *
     * @param <T>
     * @param action an instance of the TlsAction class under test, filled with custom values
     * @param logger the logger to which messages are logged
     * @see #marshalingAndUnmarshalingFilledObjectYieldsEqualObject(TlsAction)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingFilledObjectYieldsEqualObject(
            T action, Logger logger) {
        StringWriter writer = new StringWriter();

        action.filter();
        JAXB.marshal(action, writer);
        TlsAction actual =
                JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), action.getClass());
        action.normalize();
        actual.normalize();

        assertEquals(action, actual);
    }

    private ActionTestUtils() {}
}
