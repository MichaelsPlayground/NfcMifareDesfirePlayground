package de.androidcrypto.nfcmifaredesfireplayground;

import android.util.Log;

import com.github.skjolber.desfire.ev1.model.file.DesfireFileCommunicationSettings;

import java.util.Arrays;

import nfcjlib.core.KeyType;
import nfcjlib.core.util.AES;
import nfcjlib.core.util.CRC16;
import nfcjlib.core.util.CRC32;
import nfcjlib.core.util.TripleDES;

public class Cryp {

    private static final String TAG = "Cryp";

    private byte[] skey;
    private byte[] iv;
    private KeyType ktype = KeyType.AES;    // type of key used for authentication, fixed to AES

    /**
     * This is a class just to hold the methods for testing and not mixing
     * with other data
     */
    public Cryp(byte[] skey, byte[] iv) {
        this.skey = skey;
        this.iv = iv;
    }

    public byte[] getSkey() {
        return skey;
    }

    public byte[] getIv() {
        return iv;
    }

    /**
     * codes taken from DESFireEV1.java
     * NOTE: only the AES parts are active, all other modes are commented out - DO NOT USE THEM HERE
     */

    // encryption code (preprocessing)
    // preprocessing see line 1514: private byte[] preprocessEnciphered(byte[] apdu, int offset) {
    // for encryption of send apdu see line 1767: private static byte[] encryptApdu(byte[] apdu, int offset, byte[] sessionKey, byte[] iv, DesfireKeyType type) {
    // for encryption of sendApdu see line 48 in AES class:public static byte[] encrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
    // for crc see line 1744: private static byte[] calculateApduCRC32C(byte[] apdu) {

    // decryption code (postprocessing)
    // postprocessing see line 1633: private byte[] postprocessEnciphered(byte[] apdu, int length) {
    // for decryption of receivedApdu see line 2097 in AES class: public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
    // for CRC see line 1758: private static byte[] calculateApduCRC32R(byte[] apdu, int length) {

    /**
     * Pre-process command APDU before sending it to PICC.
     * The global IV is updated.
     *
     * <p>If not authenticated, the APDU is immediately returned.
     *
     * @param apdu     the APDU
     * @param offset   the offset of data within the command (for enciphered).
     *                 For example, credit does not encrypt the 1-byte
     *                 key number so the offset would be 1.
     * @param commSett the communication mode
     * @return For PLAIN, returns the APDU. For MACed, returns the
     * APDU with the CMAC appended. For ENCIPHERED,
     * returns the ciphered version of the APDU.
     * If an error occurs, returns <code>null</code>.
     */
    public byte[] preprocess(byte[] apdu, int offset, DesfireFileCommunicationSettings commSett) {
        if (commSett == null) {
            Log.e(TAG, "preprocess: commSett is null");
            return null;
        }
        if (skey == null) {
            Log.e(TAG, "preprocess: skey is null");
            return apdu;
        }

        switch (commSett) {
            case PLAIN:
                //return preprocessPlain(apdu);
            case PLAIN_MAC:
                //return preprocessMaced(apdu, offset);
            case ENCIPHERED:
                return preprocessEnciphered(apdu, offset);
            default:
                return null;  // never reached
        }
    }

    // new one, dedicated to AES only by AndroidCrypto
    public byte[] preprocessAes(byte[] apdu, int offset) {
        if (skey == null) {
            Log.e(TAG, "preprocess: skey is null");
            return apdu;
        }
        return preprocessEnciphered(apdu, offset);
    }


    // calculate CRC and append, encrypt, and update global IV
    public byte[] preprocessEnciphered(byte[] apdu, int offset) {
        System.out.println(printData("# preprocessEnciphered apdu", apdu) + " offset " + offset);
        byte[] ciphertext = encryptApdu(apdu, offset, skey, iv, ktype);
        System.out.println(printData("# preprocessEnciphered ciphertext", ciphertext));
        byte[] ret = new byte[5 + offset + ciphertext.length + 1];
        System.arraycopy(apdu, 0, ret, 0, 5 + offset);
        System.arraycopy(ciphertext, 0, ret, 5 + offset, ciphertext.length);
        ret[4] = (byte) (offset + ciphertext.length);

        if (ktype == KeyType.TKTDES || ktype == KeyType.AES) {
            iv = new byte[iv.length];
            System.arraycopy(ciphertext, ciphertext.length - iv.length, iv, 0, iv.length);
            System.out.println(printData("# preprocessEnciphered new IV", iv));
        }

        return ret;
    }

    public byte[] postprocessEnciphered(byte[] apdu, int length) {
        assert apdu.length >= 2;

        byte[] ciphertext = Arrays.copyOfRange(apdu, 0, apdu.length - 2);
        byte[] plaintext = recv(skey, ciphertext, ktype, iv);

        byte[] crc;
        switch (ktype) {
            case DES:
            case TDES:
                crc = calculateApduCRC16R(plaintext, length);
                break;
            case TKTDES:
            case AES:
                iv = Arrays.copyOfRange(apdu, apdu.length - 2 - iv.length, apdu.length - 2);
                crc = calculateApduCRC32R(plaintext, length);
                break;
            default:
                return null;
        }
        for (int i = 0; i < crc.length; i++) {
            if (crc[i] != plaintext[i + length]) {
                Log.e(TAG, "Received CMAC does not match calculated CMAC.");
                Log.e(TAG, "HAREDCODED COMMENTED OUT FOR RETURN NULL IN postprocessEnciphered approx line 1631");
                // todo HAREDCODED COMMENTED OUT FOR RETURN NULL
                // IN postprocessEnciphered
                //return null;
            }
        }

        return Arrays.copyOfRange(plaintext, 0, length);
    }


    /* Only data is encrypted. Headers are left out (e.g. keyNo for credit). */
    public byte[] encryptApdu(byte[] apdu, int offset, byte[] sessionKey, byte[] iv, KeyType type) {
        System.out.println(printData("# encryptApdu apdu", apdu) + " offset " + offset);
        System.out.println(printData("# encryptApdu sessionKey", sessionKey) + " " + printData("iv", iv));
        int blockSize = type == KeyType.AES ? 16 : 8;
        int payloadLen = apdu.length - 6;
        byte[] crc = null;

        switch (type) {
            case DES:
            case TDES:
                //crc = calculateApduCRC16C(apdu, offset);
                break;
            case TKTDES:
            case AES:
                crc = calculateApduCRC32C(apdu);
                break;
        }
        System.out.println(printData("# encryptApdu crc", crc));

        int padding = 0;  // padding=0 if block length is adequate
        if ((payloadLen - offset + crc.length) % blockSize != 0)
            padding = blockSize - (payloadLen - offset + crc.length) % blockSize;
        int ciphertextLen = payloadLen - offset + crc.length + padding;
        byte[] plaintext = new byte[ciphertextLen];
        System.arraycopy(apdu, 5 + offset, plaintext, 0, payloadLen - offset);
        System.arraycopy(crc, 0, plaintext, payloadLen - offset, crc.length);
        System.out.println(printData("# encryptApdu plaintext", plaintext));
        return send(sessionKey, plaintext, type, iv);
    }

    // uses nfcjLib/util/CRC32.java
    // CRC32 calculated over INS+header+data
    private byte[] calculateApduCRC32C(byte[] apdu) {
        byte[] data;

        if (apdu.length == 5) {
            data = new byte[apdu.length - 4];
        } else {
            data = new byte[apdu.length - 5];
            System.arraycopy(apdu, 5, data, 1, apdu.length - 6);
        }
        data[0] = apdu[1];

        return CRC32.get(data);
    }

    private byte[] calculateApduCRC16R(byte[] apdu, int length) {
        byte[] data = new byte[length];

        System.arraycopy(apdu, 0, data, 0, length);

        return CRC16.get(data);
    }

    // uses nfcjLib/util/CRC32.java
    private byte[] calculateApduCRC32R(byte[] apdu, int length) {
        byte[] data = new byte[length + 1];
        System.arraycopy(apdu, 0, data, 0, length);// response code is at the end
        return CRC32.get(data);
    }

    // Receiving data that needs decryption.
    private byte[] recv(byte[] key, byte[] data, KeyType type, byte[] iv) {
        switch (type) {
            case DES:
            case TDES:
                //return decrypt(key, data, DESFireEV1.DESMode.RECEIVE_MODE);
            case TKTDES:
                return TripleDES.decrypt(iv == null ? new byte[8] : iv, key, data);
            case AES:
                return AES.decrypt(iv == null ? new byte[16] : iv, key, data);
            default:
                return null;
        }
    }

    // IV sent is the global one but it is better to be explicit about it: can be null for DES/3DES
    // if IV is null, then it is set to zeros
    // Sending data that needs encryption.
    private byte[] send(byte[] key, byte[] data, KeyType type, byte[] iv) {
        switch (type) {
            case DES:
            case TDES:
                //return decrypt(key, data, DESFireEV1.DESMode.SEND_MODE);
            case TKTDES:
                return TripleDES.encrypt(iv == null ? new byte[8] : iv, key, data);
            case AES:
                return AES.encrypt(iv == null ? new byte[16] : iv, key, data);
            default:
                return null;
        }
    }

    public String printData(String dataName, byte[] data) {
        int dataLength;
        String dataString = "";
        if (data == null) {
            dataLength = 0;
            dataString = "IS NULL";
        } else {
            dataLength = data.length;
            dataString = Utils.bytesToHex(data);
        }
        StringBuilder sb = new StringBuilder();
        sb
                .append(dataName)
                .append(" length: ")
                .append(dataLength)
                .append(" data: ")
                .append(dataString);
        return sb.toString();
    }

}
