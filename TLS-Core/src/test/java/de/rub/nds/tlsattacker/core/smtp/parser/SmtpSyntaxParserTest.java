/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SmtpSyntaxParserTest {
    @Test
    void testValidMailboxes() {
        String[] validMailboxes =
                new String[] {
                    "john@mail.com",
                    "john.doe@mail.com",
                    "\"john @ \\ doe\"@gmx.de",
                    "john.doe@m-a-i-l.c-o-m",
                    "john.doe@[123.1.2.3]",
                    "'*+-/=?^_`{|}~#$@nice.org",
                    "userc@d.bar.org",
                    "test@[IPv6:2001:470:30:84:e276:63ff:fe72:3900]",
                };

        for (String validMailbox : validMailboxes) {
            assertTrue(SmtpSyntaxParser.isValidMailbox(validMailbox));
        }
    }

    @Test
    void testInvalidMailboxes() {
        String[] invalidMailboxes =
                new String[] {
                    "john doe@mail.com",
                    "\"john @ \\ doe@gmx.de",
                    "john @ \\ doe \"@gmx.de",
                    "\"john @ \\ doe \"@@gmx.de",
                    "john.doe@m-a-i-.c-o-m",
                    "john.doe@m-a-i-.c-o-m.",
                    "@mail.com",
                    ".@mail.com",
                    "john.doe@[300.1.2.3]",
                    "john.doe@[123.1.2.3.1]",
                    "john..doe@gmail.com",
                    "@",
                    "john.doe@",
                    "john.doe@-"
                };

        for (String invalidMailbox : invalidMailboxes) {
            assertFalse(SmtpSyntaxParser.isValidMailbox(invalidMailbox));
        }
    }

    @Test
    void testValidQuotedStrings() {
        String[] validQuotedStrings =
                new String[] {
                    "\"quoted-string\"", "\"\"quoted-string\"",
                };

        for (String validQuotedString : validQuotedStrings) {
            assertFalse(SmtpSyntaxParser.isNotAQuotedString(validQuotedString));
        }
    }

    @Test
    void testInvalidQuotedStrings() {
        String[] invalidQuotedStrings = new String[] {"not", "\"not", "not\"", ""};

        for (String invalidQuotedString : invalidQuotedStrings) {
            assertTrue(SmtpSyntaxParser.isNotAQuotedString(invalidQuotedString));
        }
    }

    @Test
    void testInvalidQuotedStringContent() {
        String[] invalidContents =
                new String[] {"\r\n", String.valueOf((char) 1), String.valueOf((char) 31)};

        for (String invalidContent : invalidContents) {
            assertFalse(SmtpSyntaxParser.isValidQuotedStringContent(invalidContent));
        }
    }

    @Test
    void testInvalidAtomStrings() {
        String[] invalidAtomStrings = new String[] {".", "@", "\""};

        for (String invalidAtomString : invalidAtomStrings) {
            assertFalse(SmtpSyntaxParser.isValidAtomString(invalidAtomString));
        }
    }
}
