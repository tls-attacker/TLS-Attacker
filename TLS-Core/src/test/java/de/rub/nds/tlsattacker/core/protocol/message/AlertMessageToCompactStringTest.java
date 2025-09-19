/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import org.junit.jupiter.api.Test;

public class AlertMessageToCompactStringTest {

    @Test
    public void testToCompactStringWithNullValues() {
        AlertMessage message = new AlertMessage();
        // Both level and description are null, no config set
        assertEquals("Alert(not configured,not configured)", message.toCompactString());
    }

    @Test
    public void testToCompactStringWithConfig() {
        AlertMessage message = new AlertMessage();
        // Set config with WARNING level (1) and BAD_RECORD_MAC description (20)
        message.setConfig(new byte[] {1, 20});
        assertEquals("Alert(WARNING,BAD_RECORD_MAC)", message.toCompactString());
    }

    @Test
    public void testToCompactStringWithExplicitValues() {
        AlertMessage message = new AlertMessage();
        message.setLevel(AlertLevel.FATAL.getValue());
        message.setDescription(AlertDescription.HANDSHAKE_FAILURE.getValue());
        assertEquals("Alert(FATAL,HANDSHAKE_FAILURE)", message.toCompactString());
    }

    @Test
    public void testToCompactStringWithUnknownValues() {
        AlertMessage message = new AlertMessage();
        // Use values that don't correspond to known alert types
        message.setConfig(new byte[] {99, 99});
        assertEquals("Alert(UNDEFINED,99)", message.toCompactString());
    }

    @Test
    public void testToCompactStringWithPartialConfig() {
        AlertMessage message = new AlertMessage();
        // Config with only one byte - should fall back to "not configured"
        message.setConfig(new byte[] {1});
        assertEquals("Alert(not configured,not configured)", message.toCompactString());
    }

    @Test
    public void testToCompactStringWithLevelButNoDescription() {
        AlertMessage message = new AlertMessage();
        message.setLevel(AlertLevel.WARNING.getValue());
        // Description is null, no config
        assertEquals("Alert(WARNING,not configured)", message.toCompactString());
    }

    @Test
    public void testToCompactStringWithDescriptionButNoLevel() {
        AlertMessage message = new AlertMessage();
        message.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        // Level is null, no config
        assertEquals("Alert(not configured,CLOSE_NOTIFY)", message.toCompactString());
    }

    @Test
    public void testToCompactStringPrefersExplicitValuesOverConfig() {
        AlertMessage message = new AlertMessage();
        // Set config
        message.setConfig(new byte[] {1, 20});
        // But also set explicit values - these should take precedence
        message.setLevel(AlertLevel.FATAL.getValue());
        message.setDescription(AlertDescription.UNEXPECTED_MESSAGE.getValue());
        assertEquals("Alert(FATAL,UNEXPECTED_MESSAGE)", message.toCompactString());
    }
}
