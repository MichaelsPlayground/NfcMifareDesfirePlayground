package de.androidcrypto.nfcmifaredesfireplayground;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * This class generates the payload for commands on Mifare DESFire EV1/2/3 cards
 * Note that the sanity checks limit some values for my purposes, e.g. fileSize is of maximum 32 bytes
 * Second: I do not use any offset so all data are written or read from the beginning of a file or record
 */

public class PayloadBuilder {

    /**
     * covers the create a write payloads for these file types
     * 00 = Standard Data file
     * 02 = Value files
     * 03 = Linear Records file
     * 04 = Cyclic Records file
     */

    public PayloadBuilder() {
    }

    private int MAXIMUM_FILE_SIZE = 32; // avoid framing

    /**
     * section for file type 00 = Standard Files
     */

    public byte[] createStandardFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if ((keyRW < 0) || (keyRW > 15)) return null;
        if ((keyCar < 0) || (keyCar > 15)) return null;
        if ((keyR < 0) || (keyR > 15)) return null;
        if ((keyW < 0) || (keyW > 15)) return null;
        if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) return null;

        // build
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03; // todo check on this later
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] payload = new byte[7];
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 4, 3);
        return payload;
    }

    public byte[] writeToStandardFile(int fileNumber, String data) {
        return writeToStandardFile(fileNumber, data.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] writeToStandardFile(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if (data == null) return null;
        if (data.length > MAXIMUM_FILE_SIZE) return null; // avoid framing

        // build
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = intTo3ByteArrayLsb(data.length);
        byte[] payload = new byte[7 + data.length]; // 7 + length of data
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(offset, 0, payload, 1, 3);
        System.arraycopy(lengthOfData, 0, payload, 4, 3);
        System.arraycopy(data, 0, payload, 7, data.length);
        return payload;
    }

    /**
     * section for file type 02 = Value Files
     */

    // note: a lot of limits are applied to parameters
    public byte[] createValueFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int lowerLimit, int upperLimit, int value) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if ((keyRW < 0) || (keyRW > 15)) return null;
        if ((keyCar < 0) || (keyCar > 15)) return null;
        if ((keyR < 0) || (keyR > 15)) return null;
        if ((keyW < 0) || (keyW > 15)) return null;
        if ((lowerLimit < 0) || (lowerLimit > 100)) return null;
        if ((upperLimit < 0) || (upperLimit > 100)) return null;
        if (upperLimit <= lowerLimit) return null;
        if ((value < 0) || (value > 100)) return null;

        // build
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03; // todo check on this later
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0

        byte[] payload = new byte[17]; // just to show the length
        byte[] lowerLimitByte = intTo4Byte_le(lowerLimit);
        byte[] upperLimitByte = intTo4Byte_le(upperLimit);
        byte[] valueByte = intTo4Byte_le(value);
        byte limitedCreditOperationEnabled = (byte) 0x00; // 00 means not enabled, 1 means enabled feature
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(lowerLimitByte, 0, payload, 4, 4);
        System.arraycopy(upperLimitByte, 0, payload, 8, 4);
        System.arraycopy(valueByte, 0, payload, 12, 4);
        payload[16] = limitedCreditOperationEnabled;
        return payload;
    }

    public byte[] creditValueFile(int fileNumber, int creditValue) {
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if ((creditValue < 0) || (creditValue > 50)) return null;

        // build
        byte[] payload = new byte[5];
        byte[] value = intTo4Byte_le(creditValue);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(value, 0, payload, 1, 4);
        return payload;
    }

    // the debitValue needs to be positive
    public byte[] debitValueFile(int fileNumber, int debitValue) {
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if ((debitValue < 0) || (debitValue > 50)) return null;

        // build
        byte[] payload = new byte[5];
        byte[] value = intTo4Byte_le(debitValue);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(value, 0, payload, 1, 4);
        return payload;
    }

    /**
     * section for file type 03 = Linear Records Files
     */

    public byte[] createLinearRecordsFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize, int maximumRecords) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if ((keyRW < 0) || (keyRW > 15)) return null;
        if ((keyCar < 0) || (keyCar > 15)) return null;
        if ((keyR < 0) || (keyR > 15)) return null;
        if ((keyW < 0) || (keyW > 15)) return null;
        if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) return null;
        if ((maximumRecords < 1) || (maximumRecords > 15)) return null;

        // build
        byte[] payload = new byte[10]; // just to show the length
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03; // todo check on this later
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] maximumRecordsByte = intTo3ByteArrayLsb(maximumRecords);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 4, 3);
        System.arraycopy(maximumRecordsByte, 0, payload, 7, 3);
        return payload;
    }

    public byte[] writeToLinearRecordsFile(int fileNumber, String data) {
        return writeToLinearRecordsFile(fileNumber, data.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] writeToLinearRecordsFile(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if (data == null) return null;
        if (data.length > MAXIMUM_FILE_SIZE) return null;

        // build
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = intTo3ByteArrayLsb(data.length);
        byte[] payload = new byte[7 + data.length]; // 7 + length of data
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(offset, 0, payload, 1, 3);
        System.arraycopy(lengthOfData, 0, payload, 4, 3);
        System.arraycopy(data, 0, payload, 7, data.length);
        return payload;
    }

    /**
     * section for file type 04 = Cyclic Records Files
     */

    // as a new record is temporary stored the maximum number needs to be maximum + 1,
    // so the minimum on this field is 2
    public byte[] createCyclicRecordsFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize, int maximumRecords) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if ((keyRW < 0) || (keyRW > 15)) return null;
        if ((keyCar < 0) || (keyCar > 15)) return null;
        if ((keyR < 0) || (keyR > 15)) return null;
        if ((keyW < 0) || (keyW > 15)) return null;
        if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) return null;
        if ((maximumRecords < 2) || (maximumRecords > 15)) return null;

        // build
        byte[] payload = new byte[10]; // just to show the length
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03; // todo check on this later
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] maximumRecordsByte = intTo3ByteArrayLsb(maximumRecords);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 4, 3);
        System.arraycopy(maximumRecordsByte, 0, payload, 7, 3);
        return payload;
    }

    public byte[] writeToCyclicRecordsFile(int fileNumber, String data) {
        return writeToCyclicRecordsFile(fileNumber, data.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] writeToCyclicRecordsFile(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > 15)) return null;
        if (data == null) return null;
        if (data.length > MAXIMUM_FILE_SIZE) return null;

        // build
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = intTo3ByteArrayLsb(data.length);
        byte[] payload = new byte[7 + data.length]; // 7 + length of data
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(offset, 0, payload, 1, 3);
        System.arraycopy(lengthOfData, 0, payload, 4, 3);
        System.arraycopy(data, 0, payload, 7, data.length);
        return payload;
    }

    public enum CommunicationSetting{
        Plain, MACed, Encrypted
    }

    // converts an int to a 3 byte long array inversed = LSB style
    private byte[] intTo3ByteArrayLsb(int value) {
        return new byte[] {
                (byte)value,
                (byte)(value >> 8),
                (byte)(value >> 16)};
    }

    // conversions see https://stackoverflow.com/a/10380460/8166854
    private byte[] intTo4Byte_le(int myInteger){
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(myInteger).array();
    }

    private int byte4ToInt_le(byte [] byteArray){
        return ByteBuffer.wrap(byteArray).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private byte[] intTo4Byte_be(int myInteger){
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(myInteger).array();
    }

    private int byte4ToInt_be(byte [] byteArray){
        return ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN).getInt();
    }

}
