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
 * Some convenience methods for common tests.
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ActionTestUtils {

    public static <T extends TlsAction> void marshalingEmptyActionYieldsMinimalOutput(Class<T> actionClass) {
        marshalingEmptyActionYieldsMinimalOutput(actionClass, LogManager.getLogger(actionClass));
    }

    /**
     * Check if serialization in WorkflowTrace JAXB context works and yields
     * minimal output. If this test fails and the output shows a "wrong" class
     * name, i.e. TlsAction, check that a proper @XmlElement() annotation for
     * the class exists for the WorkflowTrace.tlsActions field. You can be sure
     * that it's missing if you see xmlns:xsi schema values in the output.
     */
    public static <T extends TlsAction> void marshalingEmptyActionYieldsMinimalOutput(Class<T> actionClass,
            Logger logger) {
        try {
            WorkflowTrace trace = new WorkflowTrace(Config.createConfig());
            T action = actionClass.newInstance();
            trace.addTlsAction(action);
            StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
            sb.append("<workflowTrace>\n");
            sb.append("    <").append(action.getClass().getSimpleName()).append("/>\n");
            sb.append("</workflowTrace>\n");
            String expected = sb.toString();

            String actual = WorkflowTraceSerializer.write(trace);
            logger.info(actual);

            assertThat(actual, equalTo(expected));

        } catch (JAXBException | IOException | InstantiationException | IllegalAccessException ex) {
            logger.error(ex.getLocalizedMessage(), ex);
            fail();
        }
    }

    public static <T extends TlsAction> void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(Class<T> actionClass) {
        marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(actionClass, LogManager.getLogger(actionClass));
    }

    public static <T extends TlsAction> void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(
            Class<T> actionClass, Logger logger) {
        try {
            T action = actionClass.newInstance();
            StringWriter writer = new StringWriter();
            JAXB.marshal(action, writer);
            TlsAction actual = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), actionClass);
            assertEquals(action, actual);
        } catch (InstantiationException | IllegalAccessException ex) {
            logger.error(ex.getLocalizedMessage(), ex);
            fail();
        }
    }

    public static <T extends TlsAction> void marshalingAndUnmarshalingFilledObjectYieldsEqualObject(T action) {
        marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action,
                LogManager.getLogger(action.getClass().getName()));
    }

    /**
     * Pass an instantiated child of TlsAction with some values set here to
     * verify that it marshals and un-marshals correctly.
     */
    public static <T extends TlsAction> void marshalingAndUnmarshalingFilledObjectYieldsEqualObject(T action,
            Logger logger) {
        StringWriter writer = new StringWriter();
        JAXB.marshal(action, writer);
        TlsAction actual = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), action.getClass());
        assertEquals(action, actual);
    }
}
