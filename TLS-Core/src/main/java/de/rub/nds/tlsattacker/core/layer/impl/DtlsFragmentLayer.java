/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.dtls.FragmentManager;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.ReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DtlsHandshakeMessageFragmentParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DtlsHandshakeMessageFragmentPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

public class DtlsFragmentLayer extends ProtocolLayer<RecordLayerHint, DtlsHandshakeMessageFragment> {

    private static Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    private FragmentManager fragmentManager;

    private int readHandshakeMessageSequence = 0;
    private int writeHandshakeMessageSequence = 0;

    public DtlsFragmentLayer(TlsContext context) {
        super(ImplementedLayers.DTLS_FRAGMENT);
        this.context = context;
        this.fragmentManager = new FragmentManager(context.getConfig());
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<DtlsHandshakeMessageFragment> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (DtlsHandshakeMessageFragment fragment : configuration.getContainerList()) {
                DtlsHandshakeMessageFragmentPreparator preparator = fragment.getPreparator(context);
                preparator.prepare();
                DtlsHandshakeMessageFragmentSerializer serializer = fragment.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                fragment.setCompleteResultingMessage(serializedMessage);
                getLowerLayer().sendData(new RecordLayerHint(fragment.getProtocolMessageType()), serializedMessage);
                addProducedContainer(fragment);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult<DtlsHandshakeMessageFragment> sendData(RecordLayerHint hint, byte[] data)
        throws IOException {
        if (hint.getType() == ProtocolMessageType.HANDSHAKE) {
            List<DtlsHandshakeMessageFragment> fragments = getEnoughFragments(context, data.length);
            fragments = wrapInFragments(
                HandshakeMessageType.getMessageType(data[0]), Arrays.copyOfRange(data,
                    HandshakeByteLength.MESSAGE_TYPE + HandshakeByteLength.MESSAGE_LENGTH_FIELD, data.length),
                fragments);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (DtlsHandshakeMessageFragment fragment : fragments) {
                fragment.getPreparator(context).prepare();
                try {
                    byte[] completeMessage = fragment.getSerializer(context).serialize();
                    fragment.setCompleteResultingMessage(completeMessage);
                    stream.write(fragment.getCompleteResultingMessage().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write Record bytes to ByteArrayStream", ex);
                }
                addProducedContainer(fragment);
            }
            getLowerLayer().sendData(hint, stream.toByteArray());
            return new LayerProcessingResult<>(fragments, getLayerType(), true);
        } else {
            getLowerLayer().sendData(hint, data);
            return new LayerProcessingResult<>(new LinkedList<>(), getLayerType(), true);
        }
    }

    @Override
    public LayerProcessingResult receiveData() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint desiredHint) throws IOException {
        ReceiveLayerConfiguration layerConfig = (ReceiveLayerConfiguration) getLayerConfiguration();
        try {
            HintedInputStream dataStream = null;
            do {
                dataStream = getLowerLayer().getDataStream();
                if (dataStream.getHint() == null) {
                    LOGGER.warn(
                        "The DTLS fragment layer requires a processing hint. E.g. a record type. Parsing as an unknown fragment");
                    currentInputStream = new HintedLayerInputStream(null, this);
                    currentInputStream.extendStream(dataStream.readAllBytes());
                } else if (dataStream.getHint() instanceof RecordLayerHint) {
                    RecordLayerHint tempHint = (RecordLayerHint) dataStream.getHint();
                    if (tempHint.getType() == ProtocolMessageType.HANDSHAKE) {
                        DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment();
                        fragment.setEpoch(tempHint.getEpoch());
                        DtlsHandshakeMessageFragmentParser parser = fragment.getParser(context,
                            new ByteArrayInputStream(dataStream.readChunk(dataStream.available())));
                        parser.parse(fragment);
                        fragment.setCompleteResultingMessage(fragment.getSerializer(context).serialize());
                        fragmentManager.addMessageFragment(fragment);
                        List<DtlsHandshakeMessageFragment> uninterpretedMessageFragments =
                            fragmentManager.getOrderedCombinedUninterpretedMessageFragments(true, false);
                        if (!uninterpretedMessageFragments.isEmpty()) {
                            DtlsHandshakeMessageFragment uninterpretedMessageFragment =
                                uninterpretedMessageFragments.get(0);
                            addProducedContainer(uninterpretedMessageFragment);
                            RecordLayerHint currentHint =
                                new RecordLayerHint(uninterpretedMessageFragment.getProtocolMessageType(),
                                    uninterpretedMessageFragment.getMessageSequence().getValue());
                            byte type = uninterpretedMessageFragment.getType().getValue();
                            byte[] content = uninterpretedMessageFragment.getMessageContent().getValue();
                            byte[] message = ArrayConverter.concatenate(new byte[] { type },
                                ArrayConverter.intToBytes(content.length, HandshakeByteLength.MESSAGE_LENGTH_FIELD),
                                content);
                            if (desiredHint == null || currentHint.equals(desiredHint)) {
                                currentInputStream = new HintedLayerInputStream(currentHint, this);
                                currentInputStream.extendStream(message);
                            } else {
                                nextInputStream = new HintedLayerInputStream(currentHint, this);
                                nextInputStream.extendStream(message);
                            }
                        } else {
                            currentInputStream = null;
                        }
                    } else {
                        currentInputStream = new HintedLayerInputStream(tempHint, this);
                        currentInputStream.extendStream(dataStream.readChunk(dataStream.available()));
                    }
                }
            } while (layerConfig.successRequiresMoreContainers(getLayerResult().getUsedContainers())
                || layerConfig.isProcessTrailingContainers());
            // || dataStream.available() > 0 || currentInputStream == null);
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.warn("Reached end of stream, cannot parse more dtls fragments", ex);
        }
    }

    private List<DtlsHandshakeMessageFragment> getEnoughFragments(TlsContext context, int length) {
        List<DtlsHandshakeMessageFragment> toFillList = new LinkedList<>();
        int fragmentLength = 0;
        while (fragmentLength < length) {
            DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment(context.getConfig());
            toFillList.add(fragment);
            fragmentLength += fragment.getMaxFragmentLengthConfig();
        }
        return toFillList;
    }

    private List<DtlsHandshakeMessageFragment> wrapInFragments(HandshakeMessageType type, byte[] handshakeBytes,
        List<DtlsHandshakeMessageFragment> fragments) {
        int currentOffset = 0;
        for (DtlsHandshakeMessageFragment fragment : fragments) {
            Integer maxFragmentLength = fragment.getMaxFragmentLengthConfig();
            if (maxFragmentLength == null) {
                maxFragmentLength = context.getConfig().getDtlsMaximumFragmentLength();
            }
            byte[] fragmentBytes = Arrays.copyOfRange(handshakeBytes, currentOffset,
                Math.min(currentOffset + maxFragmentLength, handshakeBytes.length));
            fragment.setHandshakeMessageTypeConfig(type);
            fragment.setFragmentContentConfig(fragmentBytes);
            fragment.setMessageSequenceConfig(writeHandshakeMessageSequence);
            increaseWriteHandshakeMessageSequence();
            fragment.setOffsetConfig(currentOffset);
            fragment.setHandshakeMessageLengthConfig(handshakeBytes.length);
            currentOffset += fragmentBytes.length;
        }
        return fragments;
    }

    public DtlsHandshakeMessageFragment wrapInSingleFragment(TlsContext context, HandshakeMessage message,
        boolean goingToBeSent) {
        DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment();
        fragment.setHandshakeMessageTypeConfig(message.getHandshakeMessageType());
        byte[] messageContent = message.getSerializer(context).serializeProtocolMessageContent();
        fragment.setFragmentContentConfig(messageContent);
        if (message.getMessageSequence() == null) {
            int messageSequence = goingToBeSent ? writeHandshakeMessageSequence : readHandshakeMessageSequence;
            fragment.setMessageSequenceConfig(messageSequence);
        } else {
            fragment.setMessageSequenceConfig(message.getMessageSequence().getValue());
        }
        fragment.setOffsetConfig(0);
        fragment.setHandshakeMessageLengthConfig(messageContent.length);
        fragment.getPreparator(context).prepare();
        byte[] completeMessage = fragment.getSerializer(context).serialize();
        fragment.setCompleteResultingMessage(completeMessage);
        return fragment;
    }

    public void resetFragmentManager(Config config) {
        fragmentManager = new FragmentManager(config);
    }

    public FragmentManager getFragmentManager() {
        return fragmentManager;
    }

    public int getReadHandshakeMessageSequence() {
        return readHandshakeMessageSequence;
    }

    public void setReadHandshakeMessageSequence(int readHandshakeMessageSequence) {
        this.readHandshakeMessageSequence = readHandshakeMessageSequence;
    }

    public void increaseReadHandshakeMessageSequence() {
        readHandshakeMessageSequence++;
    }

    public int getWriteHandshakeMessageSequence() {
        return writeHandshakeMessageSequence;
    }

    public void setWriteHandshakeMessageSequence(int writeHandshakeMessageSequence) {
        this.writeHandshakeMessageSequence = writeHandshakeMessageSequence;
    }

    public void increaseWriteHandshakeMessageSequence() {
        writeHandshakeMessageSequence++;
    }
}
