/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

/**
 * Defines behavior options for TLS workflow actions. These options control how actions handle
 * unexpected messages or failure conditions during execution.
 *
 * <p>These options can be set on individual actions in workflow traces or globally in the
 * configuration to modify the default behavior of message reception and action execution.
 */
public enum ActionOption {
    /**
     * Ignores unexpected NewSessionTicket messages received during action execution.
     *
     * <p>In TLS 1.3, servers may send NewSessionTicket messages after the handshake at any time.
     * This option prevents these messages from causing action failures when they are not explicitly
     * expected.
     */
    IGNORE_UNEXPECTED_NEW_SESSION_TICKETS,

    /**
     * Ignores unexpected warning-level alert messages.
     *
     * <p>Warning alerts (like close_notify) may be sent at various points in the connection. This
     * option allows actions to continue execution when such warnings are received unexpectedly.
     */
    IGNORE_UNEXPECTED_WARNINGS,

    /**
     * Ignores unexpected KeyUpdate messages in TLS 1.3 connections.
     *
     * <p>TLS 1.3 allows either party to update keys at any time using KeyUpdate messages. This
     * option prevents these messages from interrupting the expected message flow.
     */
    IGNORE_UNEXPECTED_KEY_UPDATE_MESSAGES,

    /**
     * Ignores unexpected application data messages.
     *
     * <p>Application data may be sent at any time after the handshake. This option allows actions
     * to continue when application data is received but not explicitly expected in the workflow.
     */
    IGNORE_UNEXPECTED_APP_DATA,

    /**
     * Ignores unexpected HTTPS/HTTP messages.
     *
     * <p>When testing HTTPS connections, HTTP messages may be received. This option prevents these
     * messages from causing action failures when focusing on TLS-level behavior.
     */
    IGNORE_UNEXPECTED_HTTPS_MESSAGES,

    /**
     * Ignores ACK messages (typically used in QUIC).
     *
     * <p>In protocols like QUIC that use TLS, ACK frames may be received. This option allows
     * ignoring such protocol-specific acknowledgment messages.
     */
    IGNORE_ACK_MESSAGES,

    /**
     * Allows the action to fail without causing the entire workflow to fail.
     *
     * <p>This option is useful for actions that may legitimately fail in certain scenarios, such as
     * when testing error conditions or optional protocol features. The workflow continues execution
     * even if this action fails.
     */
    MAY_FAIL,

    /**
     * Only checks for explicitly expected messages, ignoring all others.
     *
     * <p>When this option is set, the action only validates that expected messages are received in
     * the correct order, but does not fail if additional unexpected messages are present. This is
     * less strict than the default behavior.
     */
    CHECK_ONLY_EXPECTED,
    QUIC_FRAMES_STRICT_PADDING,
    QUIC_FRAMES_IGNORE_NT_NCID_RTCID,
    QUIC_FRAMES_IGNORE_ACK,
    QUIC_DO_NOT_ACK_RECEPTION_OF_PACKET;
    ;
}
