/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.layer.LayerStackFactory;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

public class StarttlsDelegateTest extends AbstractDelegateTest<StarttlsDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new StarttlsDelegate());
    }

    /** Test of getStarttlsType method, of class StarttlsDelegate. */
    @Test
    public void testGetStarttlsType() {
        args = new String[2];
        args[0] = "-starttls";
        args[1] = "POP3";
        delegate.setStarttlsType(null);
        assertNotSame(StarttlsType.NONE, delegate.getStarttlsType());
        jcommander.parse(args);
        assertSame(StarttlsType.POP3, delegate.getStarttlsType());
    }

    /** Test of setStarttlsType method, of class StarttlsDelegate. */
    @Test
    public void testSetStarttlsType() {
        assertSame(StarttlsType.NONE, delegate.getStarttlsType());
        delegate.setStarttlsType(StarttlsType.POP3);
        assertSame(StarttlsType.POP3, delegate.getStarttlsType());
    }

    /** Test of applyDelegate method, of class StarttlsDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = new Config();
        args = new String[2];
        args[0] = "-starttls";
        args[1] = "POP3";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(StarttlsType.POP3, config.getStarttlsType());
    }

    /** -starttls FTP must select the generic STARTTLS layer stack. */
    @Test
    public void testApplyDelegateFtp() {
        Config config = new Config();
        args = new String[] {"-starttls", "FTP"};

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(StarttlsType.FTP, config.getStarttlsType());
        assertSame(
                StackConfiguration.GENERIC_OPPORTUNISTIC_TLS,
                config.getDefaultLayerConfiguration());
    }

    /**
     * A config that already committed to SSL2 (e.g. the scanner's ssl2Only.config used by the DROWN
     * and SSL2 protocol version probes) must keep an SSL2 layer under -starttls FTP, otherwise the
     * SSL2 messages of the workflow have no layer to be handled by.
     */
    @Test
    public void testApplyDelegateFtpKeepsSsl2Stack() {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SSL2);
        args = new String[] {"-starttls", "FTP"};

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(StarttlsType.FTP, config.getStarttlsType());
        assertSame(
                StackConfiguration.GENERIC_OPPORTUNISTIC_SSL2,
                config.getDefaultLayerConfiguration());
    }

    /** A config that did not choose SSL2 still gets the regular opportunistic TLS stack. */
    @Test
    public void testApplyDelegateFtpKeepsTlsStackForNonSsl2Config() {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.TLS);
        args = new String[] {"-starttls", "FTP"};

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(StarttlsType.FTP, config.getStarttlsType());
        assertSame(
                StackConfiguration.GENERIC_OPPORTUNISTIC_TLS,
                config.getDefaultLayerConfiguration());
    }

    /**
     * A STARTTLS upgrade must not toggle the global stop-after-unexpected flag. A refused upgrade
     * (e.g. FTP 4xx/5xx instead of 234) is aborted by the ReceiveRegexTextAction itself when the
     * reply can no longer match, so the global flag stays at its default and the subsequent TLS
     * handshake keeps its normal, permissive receive behavior for scanning.
     */
    @Test
    public void testApplyDelegateFtpLeavesGlobalStopTraceFlagUntouched() {
        Config config = new Config();
        args = new String[] {"-starttls", "FTP"};

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertFalse(config.isStopTraceAfterUnexpected());
    }

    /** Without STARTTLS the stop-after-unexpected flag keeps its default (off). */
    @Test
    public void testApplyDelegateNoneLeavesStopTraceDefault() {
        Config config = new Config();
        delegate.setStarttlsType(StarttlsType.NONE);

        delegate.applyDelegate(config);

        assertSame(StarttlsType.NONE, config.getStarttlsType());
        assertFalse(config.isStopTraceAfterUnexpected());
    }

    /** Without STARTTLS the layer configuration of the config is left untouched. */
    @Test
    public void testApplyDelegateNoneKeepsLayerConfiguration() {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SSL2);
        delegate.setStarttlsType(StarttlsType.NONE);

        delegate.applyDelegate(config);

        assertSame(StackConfiguration.SSL2, config.getDefaultLayerConfiguration());
    }

    /** The types with a dedicated protocol layer keep selecting their own stack. */
    @ParameterizedTest
    @CsvSource({"POP3, POP3", "SMTP, SMTP"})
    public void testApplyDelegateSelectsDedicatedStack(
            StarttlsType starttlsType, StackConfiguration expectedStack) {
        Config config = new Config();
        delegate.setStarttlsType(starttlsType);

        delegate.applyDelegate(config);

        assertSame(expectedStack, config.getDefaultLayerConfiguration());
    }

    /**
     * A type with a dedicated protocol layer has no SSL2 variant yet, so a config that committed to
     * SSL2 still gets the stack of the protocol. This pins the current behavior, it is not a
     * statement that SSL2 works for these protocols.
     */
    @ParameterizedTest
    @CsvSource({"POP3, POP3", "SMTP, SMTP"})
    public void testApplyDelegateWithoutSsl2VariantIgnoresSsl2Config(
            StarttlsType starttlsType, StackConfiguration expectedStack) {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SSL2);
        delegate.setStarttlsType(starttlsType);

        delegate.applyDelegate(config);

        assertSame(expectedStack, config.getDefaultLayerConfiguration());
    }

    /**
     * Every StartTLS type that negotiates the upgrade with plain text actions must use the generic
     * opportunistic stacks. Adding such a protocol is meant to be a single constant in {@link
     * StarttlsType}, so a new type that silently deviates from this is a mistake.
     */
    @ParameterizedTest
    @EnumSource(
            value = StarttlsType.class,
            names = {"NONE", "POP3", "SMTP"},
            mode = EnumSource.Mode.EXCLUDE)
    public void testLightweightTypesUseGenericStacks(StarttlsType starttlsType) {
        assertSame(StackConfiguration.GENERIC_OPPORTUNISTIC_TLS, starttlsType.getStack());
        assertSame(StackConfiguration.GENERIC_OPPORTUNISTIC_SSL2, starttlsType.getSsl2Stack());
    }

    /** Every StartTLS type must resolve to a stack the layer stack factory can build. */
    @ParameterizedTest
    @EnumSource(value = StarttlsType.class, names = "NONE", mode = EnumSource.Mode.EXCLUDE)
    public void testResolvedStacksAreBuildable(StarttlsType starttlsType) {
        Context context = new Context(new State(new Config()), new InboundConnection());

        assertNotNull(
                LayerStackFactory.createLayerStack(
                        starttlsType.resolveStack(StackConfiguration.TLS), context));
        assertNotNull(
                LayerStackFactory.createLayerStack(
                        starttlsType.resolveStack(StackConfiguration.SSL2), context));
    }
}
