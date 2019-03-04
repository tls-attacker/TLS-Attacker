/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.unittest.helper.DefaultNormalizeFilter;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * Convenience methods for common TlsAction tests.
 */
public class ActionTestUtils {

    /**
     * Verify that the given TlsACtion can be marshaled to minimal output.
     * <p>
     * Same as this.marshalingEmptyActionYieldsMinimalOutput(Class<T>, Logger),
     * but sets the logger automatically.
     * <p>
     * 
     * @param <T>
     * @param actionClass
     *            the Class to test
     * @see this.marshalingEmptyActionYieldsMinimalOutput(Class<T>, Logger)
     */
    public static <T extends TlsAction> void marshalingEmptyActionYieldsMinimalOutput(Class<T> actionClass) {
        marshalingEmptyActionYieldsMinimalOutput(actionClass, LogManager.getLogger(actionClass));
    }

    /**
     * Verify that the given TlsACtion can be marshaled to minimal output.
     * <p>
     * Test has two purposes
     * <ol>
     * <li>Verify that the action class is known to the JAXB context</li>
     * <li>Verify that marshaling of an empty instance yields minimal output</li>
     * </ol>
     * <p>
     * If this test fails and the output shows a "wrong" class name, i.e.
     * TlsAction, check that a proper @XmlElement() annotation for the class
     * exists for the WorkflowTrace.tlsActions field. You can be sure that it's
     * missing if you see xmlns:xsi schema values in the output.
     * <p>
     * Calling this method is expensive, since it goes through the whole
     * normalize/filter/serialize procedure. <b>Should be invoked by tests in
     * Category(SlowTests.class) only</b>
     * 
     * @param <T>
     * @param actionClass
     *            the Class to test
     * @param logger
     *            the logger to which messages are written to
     * @see this.marshalingEmptyActionYieldsMinimalOutput(Class<T>)
     */
    public static <T extends TlsAction> void marshalingEmptyActionYieldsMinimalOutput(Class<T> actionClass,
            Logger logger) {
        try {
            WorkflowTrace trace = new WorkflowTrace();
            T action = actionClass.newInstance();
            trace.addTlsAction(action);
            String xmlName = action.getClass().getSimpleName();
            if (xmlName.endsWith("Action")) {
                xmlName = xmlName.substring(0, xmlName.length() - 6);
            } else {
                logger.warn("The action under test does not follow naming convention. " + xmlName
                        + " does not end with string 'Action'");
            }
            StringBuilder sb = new StringBuilder("");
            sb.append("<workflowTrace>").append(System.lineSeparator());
            sb.append("    <").append(xmlName).append("/>").append(System.lineSeparator());
            sb.append("</workflowTrace>").append(System.lineSeparator());
            String expected = sb.toString();

            Config config = Config.createConfig();
            // We don't need to keep user settings. Skip for better performance.
            config.setFiltersKeepUserSettings(false);
            DefaultNormalizeFilter.normalizeAndFilter(trace, config);
            String actual = WorkflowTraceSerializer.write(trace);
            logger.info(actual);

            assertThat(actual, equalTo(expected));

        } catch (JAXBException | IOException | InstantiationException | IllegalAccessException ex) {
            logger.error(ex.getLocalizedMessage(), ex);
            fail();
        }
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for empty action equals
     * original action.
     * <p>
     * Same as
     * this.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(Class<T>,
     * Logger), but sets the logger automatically.
     * <p>
     * 
     * @param <T>
     * @param actionClass
     *            the Class to test
     * @see this.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(Class<T>,
     *      Logger)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(Class<T> actionClass) {
        marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(actionClass, LogManager.getLogger(actionClass));
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for empty action equals
     * original action.
     * <p>
     * "Empty" action refers to a TlsAction instance initialized with empty
     * constructor and without any additional values set.
     * <p>
     * Calling this method is expensive. <b>Should be invoked by tests in
     * 
     * @param <T>
     * @Category(SlowTests.class) only</b>
     *                            <p>
     * 
     * @param actionClass
     *            the Class to test
     * @param logger
     *            to which messages are written to
     * @see this.marshalingEmptyActionYieldsMinimalOutput(Class<T>)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(
            Class<T> actionClass, Logger logger) {
        try {
            T action = actionClass.newInstance();
            StringWriter writer = new StringWriter();

            action.filter();
            JAXB.marshal(action, writer);
            TlsAction actual = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), actionClass);
            action.normalize();
            actual.normalize();

            assertEquals(action, actual);
        } catch (InstantiationException | IllegalAccessException ex) {
            logger.error(ex.getLocalizedMessage(), ex);
            fail();
        }
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for non-empty action equals
     * original action.
     * <p>
     * Same as
     * this.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(Class<T>,
     * Logger), but sets the logger automatically.
     * <p>
     * 
     * @param <T>
     * @param action
     *            an instance of the TlsAction class under test, filled with
     *            custom values
     * @see 
     *      this.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(Class<T>,
     *      Logger)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingFilledObjectYieldsEqualObject(T action) {
        marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action,
                LogManager.getLogger(action.getClass().getName()));
    }

    /**
     * Verify that unmarshal(marshal(TlsAction)) for non-empty action equals
     * original action.
     * <p>
     * "Non-empty" or "filled" action refers to a TlsAction instance which has
     * some custom values set.
     * <p>
     * Calling this method is expensive. <b>Should be invoked by tests in
     * Category(SlowTests.class) only</b>
     * <p>
     * 
     * @param <T>
     * @param action
     *            an instance of the TlsAction class under test, filled with
     *            custom values
     * @param logger
     *            the logger to which messages are logged
     * @see 
     *      this.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(Class<T>)
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingFilledObjectYieldsEqualObject(T action,
            Logger logger) {
        StringWriter writer = new StringWriter();

        action.filter();
        JAXB.marshal(action, writer);
        TlsAction actual = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), action.getClass());
        action.normalize();
        actual.normalize();

        assertEquals(action, actual);
    }

    private ActionTestUtils() {
    }
}
