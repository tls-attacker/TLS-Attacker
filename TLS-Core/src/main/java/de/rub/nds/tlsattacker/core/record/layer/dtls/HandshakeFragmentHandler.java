/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.layer.dtls;

public class HandshakeFragmentHandler {
    //
    // private static final Logger LOGGER =
    // LogManager.getLogger(HandshakeFragmentHandler.class);
    //
    // final Map<Integer, List<Record>> handshakeMessageRecordMap = new
    // HashMap<>();
    //
    // final Map<Integer, BitSet> handshakeMessageReassembleBitmaskMap = new
    // HashMap<>();
    //
    // final Map<Integer, byte[]> reassembledHandshakeMessageMap = new
    // HashMap<>();
    //
    // private int expectedHandshakeMessageSeq;
    //
    // public void processHandshakeRecord(Record handshakeRecord) {
    // byte[] recordData = handshakeRecord.getProtocolMessageBytes().getValue();
    // List<Integer> affectedHandshakeMessages = new ArrayList<>();
    // int workPointer = 0;
    // byte handshakeMessageType;
    // int handshakeMessageSize;
    // int handshakeMessageSeq;
    // int handshakeMessageFragOffset;
    // int handshakeMessageFragSize;
    //
    // while ((workPointer + 12) <= recordData.length) {
    // handshakeMessageSeq = (recordData[workPointer + 4] << 8) +
    // (recordData[workPointer + 5] & 0xFF);
    // handshakeMessageFragSize = (recordData[workPointer + 9] << 16) +
    // (recordData[workPointer + 10] << 8)
    // + (recordData[workPointer + 11] & 0xFF);
    //
    // if (handshakeMessageSeq < expectedHandshakeMessageSeq
    // || checkHandshakeMessageAvailable(handshakeMessageSeq)) {
    // workPointer += handshakeMessageFragSize + 12;
    // continue;
    // }
    //
    // handshakeMessageFragOffset = (recordData[workPointer + 6] << 16) +
    // (recordData[workPointer + 7] << 8)
    // + (recordData[workPointer + 8] & 0xFF);
    // handshakeMessageType = recordData[workPointer];
    // handshakeMessageSize = (recordData[workPointer + 1] << 16) +
    // (recordData[workPointer + 2] << 8)
    // + (recordData[workPointer + 3] & 0xFF);
    // workPointer += 12;
    //
    // if ((handshakeMessageFragSize + workPointer) > recordData.length) {
    // throw new MalformedMessageException(
    // "The received handshake message (fragment) claims to contain more data than it actually does.");
    // }
    // if (handshakeMessageFragSize > handshakeMessageSize) {
    // throw new MalformedMessageException(
    // "The received handshake message (fragment) claims to contain a fragment that's bigger than the actual handshake message length.");
    // }
    // if ((handshakeMessageFragOffset + handshakeMessageFragSize) >
    // handshakeMessageSize) {
    // throw new MalformedMessageException(
    // "The received handshake message fragment is out of the the handshake message bounds implicated by its handshake message length.");
    // }
    //
    // if (!affectedHandshakeMessages.contains(handshakeMessageSeq)) {
    // affectedHandshakeMessages.add(handshakeMessageSeq);
    // }
    // processHandshakeMessageFragment(handshakeMessageType,
    // handshakeMessageSize, handshakeMessageSeq,
    // handshakeMessageFragOffset, handshakeMessageFragSize, recordData,
    // workPointer);
    //
    // workPointer += handshakeMessageFragSize;
    // }
    //
    // for (Integer affectedHandshakeMessage : affectedHandshakeMessages) {
    // addHandshakeRecordToRecordMap(handshakeRecord, affectedHandshakeMessage);
    // }
    // }
    //
    // private void processHandshakeMessageFragment(byte handshakeMessageType,
    // int handshakeMessageSize,
    // int handshakeMessageSeq, int handshakeMessageFragOffset, int
    // handshakeMessageFragSize, byte[] recordData,
    // int workPointer) {
    //
    // if (createKeyInReassembleMaps(handshakeMessageSize, handshakeMessageSeq))
    // {
    // byte[] header =
    // createCompleteHandshakeMessageHeader(handshakeMessageType,
    // handshakeMessageSeq,
    // handshakeMessageSize);
    // handshakeMessageReassembleBitmaskMap.get(handshakeMessageSeq).set(0, 12,
    // true);
    // System.arraycopy(header, 0,
    // reassembledHandshakeMessageMap.get(handshakeMessageSeq), 0, 12);
    // }
    //
    // handshakeMessageReassembleBitmaskMap.get(handshakeMessageSeq).set(handshakeMessageFragOffset
    // + 12,
    // (handshakeMessageFragOffset + 12 + handshakeMessageFragSize), true);
    // System.arraycopy(recordData, workPointer,
    // reassembledHandshakeMessageMap.get(handshakeMessageSeq),
    // handshakeMessageFragOffset + 12, handshakeMessageFragSize);
    // }
    //
    // protected byte[] createCompleteHandshakeMessageHeader(byte handshakeType,
    // int handshakeMessageSeq,
    // int handshakeMessageSize) {
    // byte[] output = new byte[12];
    // output[0] = handshakeType;
    // output[1] = (byte) (handshakeMessageSize >>> 16);
    // output[2] = (byte) (handshakeMessageSize >>> 8);
    // output[3] = (byte) handshakeMessageSize;
    // output[4] = (byte) (handshakeMessageSeq >>> 8);
    // output[5] = (byte) handshakeMessageSeq;
    // output[9] = output[1];
    // output[10] = output[2];
    // output[11] = output[3];
    // return output;
    // }
    //
    // public byte[] getHandshakeMessage() {
    // if (checkHandshakeMessageAvailable(expectedHandshakeMessageSeq)) {
    // return reassembledHandshakeMessageMap.get(expectedHandshakeMessageSeq);
    // } else {
    // return null;
    // }
    // }
    //
    // protected boolean checkHandshakeMessageAvailable(int seqNum) {
    // if (reassembledHandshakeMessageMap.containsKey(seqNum)) {
    // return checkHandshakeMessageCompleteness(seqNum);
    // }
    // return false;
    // }
    //
    // private boolean checkHandshakeMessageCompleteness(int seqNum) {
    // return handshakeMessageReassembleBitmaskMap.get(seqNum).cardinality() ==
    // reassembledHandshakeMessageMap
    // .get(seqNum).length;
    // }
    //
    // private boolean createKeyInReassembleMaps(int handshakeMessageSize, int
    // seqNum) {
    // if (!handshakeMessageReassembleBitmaskMap.containsKey(seqNum)) {
    // handshakeMessageReassembleBitmaskMap.put(seqNum, new
    // BitSet(handshakeMessageSize + 12));
    // reassembledHandshakeMessageMap.put(seqNum, new byte[handshakeMessageSize
    // + 12]);
    // return true;
    // }
    // return false;
    // }
    //
    // private void addHandshakeRecordToRecordMap(Record record, int seqNum) {
    // if (handshakeMessageRecordMap.containsKey(seqNum)) {
    // handshakeMessageRecordMap.get(seqNum).add(record);
    // } else {
    // ArrayList<Record> recordList = new ArrayList<>();
    // recordList.add(record);
    // handshakeMessageRecordMap.put(seqNum, recordList);
    // }
    // }
    //
    // public void addRecordsToHandshakeMessage(ProtocolMessage
    // handshakeMessage) {
    // List<Record> recordList =
    // handshakeMessageRecordMap.get(expectedHandshakeMessageSeq);
    // handshakeMessage.setRecords(recordList);
    // }
    //
    // public void flush() {
    // handshakeMessageRecordMap.clear();
    // handshakeMessageReassembleBitmaskMap.clear();
    // reassembledHandshakeMessageMap.clear();
    // }
    //
    // public void incrementExpectedHandshakeMessageSeq() {
    // expectedHandshakeMessageSeq++;
    // }
    //
    // public byte[] fragmentHandshakeMessage(byte[] handshakeMessageBytes, int
    // maxMessageSize) {
    // maxMessageSize -= 12;
    // int messageSize = handshakeMessageBytes.length - 12;
    // int numFragments = (int) Math.ceil((double) messageSize /
    // maxMessageSize);
    // if (numFragments == 0) {
    // numFragments = 1;
    // }
    // LOGGER.debug("Splitting the handshake message into {} fragments",
    // numFragments);
    // byte[] fragmentArray = new byte[0];
    // int indexPointer, fragmentLength, fragmentSizeCounter;
    // byte[] handshakeHeader = new byte[12];
    // handshakeHeader[0] = handshakeMessageBytes[0];
    // handshakeHeader[1] = (byte) (messageSize >>> 16);
    // handshakeHeader[2] = (byte) (messageSize >>> 8);
    // handshakeHeader[3] = (byte) messageSize;
    // handshakeHeader[4] = handshakeMessageBytes[4];
    // handshakeHeader[5] = handshakeMessageBytes[5];
    //
    // for (int i = 0; i < numFragments; i++) {
    // indexPointer = i * maxMessageSize;
    // fragmentSizeCounter = messageSize - maxMessageSize * i;
    // if (fragmentSizeCounter < maxMessageSize) {
    // fragmentLength = fragmentSizeCounter;
    // } else {
    // fragmentLength = maxMessageSize;
    // }
    // handshakeHeader[6] = (byte) (indexPointer >>> 16);
    // handshakeHeader[7] = (byte) (indexPointer >>> 8);
    // handshakeHeader[8] = (byte) indexPointer;
    // handshakeHeader[9] = (byte) (fragmentLength >>> 16);
    // handshakeHeader[10] = (byte) (fragmentLength >>> 8);
    // handshakeHeader[11] = (byte) fragmentLength;
    // fragmentArray = ArrayConverter.concatenate(fragmentArray,
    // handshakeHeader,
    // Arrays.copyOfRange(handshakeMessageBytes, indexPointer + 12, indexPointer
    // + fragmentLength + 12));
    // }
    // return fragmentArray;
    // }
    //
    // public List<Record> getReceivedHandshakeMessageRecords(int seqNum) {
    // if (handshakeMessageRecordMap.containsKey(seqNum)) {
    // return handshakeMessageRecordMap.get(seqNum);
    // }
    // return new ArrayList<>();
    // }
    //
    // public void setExpectedHandshakeMessageSeq(int seqNum) {
    // expectedHandshakeMessageSeq = seqNum;
    // }
    //
    // public int getExpectedHandshakeMessageSeq() {
    // return expectedHandshakeMessageSeq;
    // }
}
