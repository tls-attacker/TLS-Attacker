package de.rub.nds.tlsattacker.core.smtp.parser;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyntaxCheckerText {
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
}
