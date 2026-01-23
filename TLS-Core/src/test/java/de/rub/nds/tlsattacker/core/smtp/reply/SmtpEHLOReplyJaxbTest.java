/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SmtpEHLOReplyJaxbTest {

    private static final String EHLO_REPLY_XML =
            "<smtpEHLOReply>"
                    + "<commandType>EHLO</commandType>"
                    + "<replyCode>250</replyCode>"
                    + "<domain>mx.google.com</domain>"
                    + "<greeting>at your service, [5.195.119.13]</greeting>"
                    + "<extensions/>"
                    + "<extensions/>"
                    + "<extensions/>"
                    + "<extensions/>"
                    + "<extensions/>"
                    + "<extensions/>"
                    + "<extensions/>"
                    + "</smtpEHLOReply>";

    @Test
    void unmarshalsEhloReplyWithEmptyExtensions() throws Exception {
        ByteArrayInputStream is =
                new ByteArrayInputStream(EHLO_REPLY_XML.getBytes(StandardCharsets.UTF_8));
        SmtpEHLOReply reply =
                assertDoesNotThrow(
                        () -> {
                            JAXBContext ctx = JAXBContext.newInstance(SmtpEHLOReply.class);
                            Unmarshaller u = ctx.createUnmarshaller();
                            return (SmtpEHLOReply) u.unmarshal(is);
                        },
                        "JAXB should unmarshal EHLO reply even with empty <extensions/> entries");

        assertNotNull(reply);
        assertEquals(SmtpCommandType.EHLO, reply.getCommandType());
        assertEquals(250, reply.getReplyCode());
        assertEquals("mx.google.com", reply.getDomain());
        assertEquals("at your service, [5.195.119.13]", reply.getGreeting());
        // Was failing previously; presence of entries confirms list was created
        assertEquals(7, reply.getExtensions().size());
    }

    @Test
    void unmarshallingFailsWithoutNoArgCtor() throws Exception {
        ByteArrayInputStream is =
                new ByteArrayInputStream(EHLO_REPLY_XML.getBytes(StandardCharsets.UTF_8));

        Throwable ex =
                assertThrows(
                        Throwable.class,
                        () -> {
                            JAXBContext ctx = JAXBContext.newInstance(SmtpEhloReplyNoCtor.class);
                            Unmarshaller u = ctx.createUnmarshaller();
                            u.unmarshal(is);
                        },
                        "Expected JAXB to fail when extensions lack no-arg ctor");

        assertNotNull(ex);
    }

    /** Minimal replica lacking a no-arg ctor for its extensions to simulate legacy failure. */
    @XmlRootElement(name = "smtpEHLOReply")
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class SmtpEhloReplyNoCtor {
        private SmtpCommandType commandType;
        private int replyCode;
        private String domain;
        private String greeting;

        @XmlElement(name = "extensions")
        private java.util.List<NoCtorExtension> extensions;
    }

    /** Extension without a no-arg constructor to trigger JAXB instantiation failure. */
    public static class NoCtorExtension {
        @jakarta.xml.bind.annotation.XmlValue private final String keyword;

        public NoCtorExtension(String keyword) {
            this.keyword = keyword;
        }

        public String getKeyword() {
            return keyword;
        }
    }
}
