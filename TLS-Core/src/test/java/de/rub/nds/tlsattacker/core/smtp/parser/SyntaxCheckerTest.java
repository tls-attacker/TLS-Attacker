package de.rub.nds.tlsattacker.core.smtp.parser;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyntaxCheckerTest {
    @Test
    void testValidMailboxes() {
        String[] validMailboxes = new String[]{
                "john@mail.com",
                "john.doe@mail.com",
                "\"john @ \\ doe\"@gmx.de",
                "john.doe@m-a-i-l.c-o-m",
                "john.doe@[123.1.2.3]"
        };

        for (String validMailbox : validMailboxes) {
            assertTrue(SyntaxChecker.isValidMailbox(validMailbox));
        }
    }

    @Test
    void testInvalidMailboxes() {
        String[] invalidMailboxes = new String[]{
                "john doe@mail.com",
                "\"john @ \\ doe@gmx.de",
                "john @ \\ doe \"@gmx.de",
                "\"john @ \\ doe \"@@gmx.de",
                "john.doe@m-a-i-.c-o-m",
                "john.doe@m-a-i-.c-o-m.",
                "@mail.com",
                ".@mail.com",
                "john.doe@[300.1.2.3]",
                "john.doe@[123.1.2.3.1]"
        };

        for (String invalidMailbox : invalidMailboxes) {
            assertFalse(SyntaxChecker.isValidMailbox(invalidMailbox));
        }
    }

    @Test
    void testValidQuotedStrings() {
        String[] validQuotedStrings = new String[]{
                "\"quoted-string\"",
                "\"\"quoted-string\"",
        };

        for (String validQuotedString : validQuotedStrings) {
            assertFalse(SyntaxChecker.isNotAQuotedString(validQuotedString));
        }
    }

    @Test
    void testInvalidQuotedStrings() {
        String[] invalidQuotedStrings = new String[]{
                "not",
                "\"not",
                "not\"",
                ""
        };

        for (String invalidQuotedString : invalidQuotedStrings) {
            assertTrue(SyntaxChecker.isNotAQuotedString(invalidQuotedString));
        }
    }

    @Test
    void testInvalidQuotedStringContent() {
        String[] invalidContents = new String[]{
                "\r\n",
                String.valueOf((char) 1),
                String.valueOf((char) 31)
        };

        for (String invalidContent : invalidContents) {
            assertFalse(SyntaxChecker.isValidQuotedStringContent(invalidContent));
        }
    }

    @Test
    void testInvalidAtomStrings() {
        String[] invalidAtomStrings = new String[]{
                ".",
                "@",
                "\""
        };

        for (String invalidAtomString: invalidAtomStrings) {
            assertFalse(SyntaxChecker.isValidAtomString(invalidAtomString));
        }
    }
}
