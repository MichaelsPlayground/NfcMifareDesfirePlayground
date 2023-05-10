package de.androidcrypto.nfcmifaredesfireplayground;

import static com.github.skjolber.desfire.libfreefare.MifareDesfire.mifare_desfire_tag_new;
import static nfcjlib.core.DESFireEV1.validateKey;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;
import com.github.skjolber.desfire.ev1.model.DesfireTag;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.file.DesfireFileCommunicationSettings;
import com.github.skjolber.desfire.libfreefare.MifareTag;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import nfcjlib.core.DESFireAdapter;
import nfcjlib.core.DESFireEV1;
import nfcjlib.core.KeyType;
import nfcjlib.core.util.AES;
import nfcjlib.core.util.CRC32;
import nfcjlib.core.util.TripleDES;


public class NdefActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private final String TAG = "Main";

    Button btn2, btn3, btn4, btn5;
    EditText tagId, dataToWrite, readResult;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte;
    IsoDep isoDep;
    Tag tagSaved;

    // vars for enhanced functions using libraries from https://github.com/skjolber/desfire-tools-for-android
    private MifareTag nfcjTag;
    private DesfireTag desfireTag;
    //private DefaultIsoDepAdapter defaultIsoDepAdapter;
    private DESFireAdapter desFireAdapter;

    /**
     * Note on all KEY data (important for DES/TDES keys only)
     * A DES key has a length 64 bits (= 8 bytes) but only 56 bits are used for encryption, the remaining 8 bits are were
     * used as parity bits and within DESFire as key version information.
     * If you are using the 'original' key you will run into authentication issues.
     * You should always strip of the parity bits by running the setKeyVersion command
     * e.g. setKeyVersion(AID_DesLog_Key2_New, 0, AID_DesLog_Key2_New.length, (byte) 0x00);
     * This will set the key version to '0x00' by setting all parity bits to '0x00'
     */


    /**
     * constants for MasterFile
     */

    private final byte[] AID_Master = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00};
    private final byte AID_Master_number_of_keys = (byte) 0x01;
    private final byte[] AID_Master_Key0 = Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte AID_Master_Key0_Number = (byte) 0x00;

    /**
     * constants for application "DesStandard", 3 DES keys, 2 files with each 32 bytes
     */

    private final byte[] AID_DesStandard = new byte[]{(byte) 0xa9, (byte) 0xa8, (byte) 0xa1};
    private final byte AID_DesStandard_number_of_keys = (byte) 0x03; // key0 general, key1 read, key2 write access
    private final byte[] AID_DesStandard_Key0 = Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte AID_DesStandard_Key0_Number = (byte) 0x00;
    private final byte[] AID_DesStandard_Key1 = Utils.hexStringToByteArray("0000000000000000");
    private final byte[] AID_DesStandard_Key1_New = Utils.hexStringToByteArray("1122119988776601");
    private final byte AID_DesStandard_Key1_Number = (byte) 0x01;
    private final byte[] AID_DesStandard_Key2 = Utils.hexStringToByteArray("0000000000000000");
    private final byte[] AID_DesStandard_Key2_new = Utils.hexStringToByteArray("1122119988776602");
    private final byte AID_DesStandard_Key2_Number = (byte) 0x02;
    private final byte DesStandardFileFileNumber1 = (byte) 0x01;
    private final byte DesStandardFileFileNumber2 = (byte) 0x02;

    /**
     * constants for application "DesValue", 3 DES keys, 1 ValueFile with increment and decrement
     */

    private final byte[] AID_DesValue = new byte[]{(byte) 0xa9, (byte) 0xa8, (byte) 0xa2};
    private final byte AID_DesValue_number_of_keys = (byte) 0x03; // key0 general, key1 read, key2 write access
    private final byte[] AID_DesValue_Key0 = Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte AID_DesValue_Key0_Number = (byte) 0x00;
    private final byte[] AID_DesValue_Key1 = Utils.hexStringToByteArray("0000000000000000");
    private final byte[] AID_DesValue_Key1_New = Utils.hexStringToByteArray("2222119988776601");
    private final byte AID_DesValue_Key1_Number = (byte) 0x01;
    private final byte[] AID_DesValue_Key2 = Utils.hexStringToByteArray("0000000000000000");
    private final byte[] AID_DesValue_Key2_new = Utils.hexStringToByteArray("2222119988776602");
    private final byte AID_DesValue_Key2_Number = (byte) 0x02;
    private final byte DesValueFileFileNumber1 = (byte) 0x02;
    private final byte DesValueFileFileNumber2 = (byte) 0x03;

    /**
     * constants for application "DesLog", 3 DES keys, 1 Cycle File with 5 (+1 spare) records with each 32 bytes
     */
    private final byte[] AID_DesLog = new byte[]{(byte) 0xa9, (byte) 0xa8, (byte) 0xa3}; // A3 A8 A9
    private final byte AID_DesLog_number_of_keys = (byte) 0x03; // key0 general, key1 read, key2 write access
    private final byte[] AID_DesLog_Key0 = Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte AID_DesLog_Key0_Number = (byte) 0x00;
    private final byte[] AID_DesLog_Key1 = Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte[] AID_DesLog_Key1_New = Utils.hexStringToByteArray("3322119988776601"); // new key, lets work on this
    private final byte AID_DesLog_Key1_Number = (byte) 0x01;
    private final byte[] AID_DesLog_Key2 = Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte[] AID_DesLog_Key2_New = Utils.hexStringToByteArray("3322119988776602"); // new key, lets work on this
    //private final byte[] AID_DesLog_Key2_New2 = Utils.hexStringToByteArray("3322119988776612"); // new key, lets work on this
    private final byte AID_DesLog_Key2_Number = (byte) 0x02;
    private final byte DesLogCyclicFileFileNumber = (byte) 0x04;
    private final byte DesLogCyclicFileNumberOfRecords = (byte) 0x06; // 5 records (+1 record as spare record for writing data before committing), fixed for this method

    /**
     * The following constants are global defined and got updated through several steps on ENCRYPTION and DECRYPTION
     */
    private KeyType ktype;    // type of key used for authentication
    private byte[] iv;        // the IV, kept updated between operations (for 3K3DES/AES)
    private byte[] skey;      // session key: set on successful authentication

    private byte[] ivOwn;        // the IV, kept updated between operations (for AES)
    private byte[] skeyOwn;      // session key: set on successful authentication


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ndef);

        tagId = findViewById(R.id.etVerifyTagId);
        dataToWrite = findViewById(R.id.etDataToWrite);
        readResult = findViewById(R.id.etVerifyResult);
        btn2 = findViewById(R.id.btn2);
        btn3 = findViewById(R.id.btn3);
        btn4 = findViewById(R.id.btn4);
        btn5 = findViewById(R.id.btn5);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        btn2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // format the tag for usage as NDEF (Tag 4 type) tag
                // see document MIFARE DESFire as Type 4 Tag AN11004.pdf

                // 1. select master application and authenticate

                // first we setup a des-key secured application
                byte[] responseData = new byte[2];

                try {
                    byte DES_MASTER_KEY_NUMBER = (byte) 0x00;
                    byte[] DES_MASTER_KEY = new byte[8]; // for the master application

                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Format the tag as Tag 4 type (NDEF)");

                    // select the master file application
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "1. MIFARE DESFire SelectApplication with AID equal to 000000h (PICC level)");
                    boolean selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                    writeToUiAppend(readResult, "selectMasterApplication result: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
/*
                    // authenticate
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "");
                    responseData = new byte[2];
                    // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                    boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, DES_MASTER_KEY_NUMBER, DES_MASTER_KEY, false, responseData);
                    writeToUiAppend(readResult, "authenticateMasterApplication result: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!authenticateMasterSuccess) {
                        writeToUiAppend(readResult, "the authenticationMaster was not successful, aborted");
                        return;
                    }
*/
                    // at this point the PICC needs these environments:

                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "");
                    byte[] AID_NDEF = Utils.hexStringToByteArray("010000");
                    byte APPLICATION_KEY_SETTINGS = (byte) 0x0F;
                    byte numberOfKeys = (byte) 0x21; // number of key: 1, TDES keys
                    //byte COMMUNICATION_SETTINGS = (byte) 0x0f;
                    byte FILE_ID_01 = (byte) 0x01;
                    byte[] ISO_FILE_ID_01 = Utils.hexStringToByteArray("03E1");
                    int FILE_01_SIZE = 15;
                    byte FILE_ID_02 = (byte) 0x02;
                    byte[] ISO_DF = Utils.hexStringToByteArray("D2760000850101"); // this is the AID for NDEF
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Create application");

                    // create the application
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "2. MIFARE DESFire CreateApplication using the default AID 000001h");
                    responseData = new byte[2];
                    boolean createApplicationSuccess = createApplicationIsoDes(readResult, AID_NDEF, APPLICATION_KEY_SETTINGS, numberOfKeys, ISO_FILE_ID_01, ISO_DF,  responseData);
                    writeToUiAppend(readResult, "createApplicationIso result: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!createApplicationSuccess) {
                        writeToUiAppend(readResult, "the createApplicationIso was not successful, aborted");
                        //return;
                    }

                    // select the application
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "3. MIFARE DESFire SelectApplication (Select previously created application)");
                    responseData = new byte[2];
                    byte[] AID_NDEF2 = Utils.hexStringToByteArray("000001");
                    //boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_NDEF2, responseData);
                    boolean selectApplicationIsoSuccess = selectApplicationIso(readResult, AID_NDEF2, responseData);
                    writeToUiAppend(readResult, "selectApplication result: " + selectApplicationIsoSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!selectApplicationIsoSuccess) {
                        writeToUiAppend(readResult, "the selectApplicationIso was not successful, aborted");
                        return;
                    }

                    // step 04 create a standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "4. MIFARE DESFire CreateStdDataFile with FileNo equal to 01h");
                    responseData = new byte[2];
                    boolean createStandardFileIsoSuccess = createStandardFileIso(readResult, FILE_ID_01, ISO_FILE_ID_01, PayloadBuilder.CommunicationSetting.Plain,
                            14, 14, 14, 14, FILE_01_SIZE, responseData);
                    writeToUiAppend(readResult, "createStandardFileIso result: " + createStandardFileIsoSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!createStandardFileIsoSuccess) {
                        writeToUiAppend(readResult, "the createStandardFileIso was not successful, aborted");
                        //return;
                    }

                    // step 05 write to standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "5. MIFARE DESFire WriteData to write the content of the CC File with CCLEN equal to 000Fh");
                    responseData = new byte[2];
                    byte[] dataToWriteByte = "hello".getBytes(StandardCharsets.UTF_8);
                    boolean writeToStandardFileNdefSuccess = writeToStandardFileNdef(readResult, FILE_ID_01, dataToWriteByte, responseData);
                    writeToUiAppend(readResult, "writeToStandardFileNdef result: " + writeToStandardFileNdefSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!writeToStandardFileNdefSuccess) {
                        writeToUiAppend(readResult, "the writeToStandardFileNdef was not successful, aborted");
                        //return;
                    }

                    // step 06 create a standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "6. MIFARE DESFire CreateStdDataFile with FileNo equal to 02h");
                    responseData = new byte[2];
                    boolean createStandardFileIsoStep06Success = createStandardFileIsoStep6(readResult, FILE_ID_02, responseData);
                    writeToUiAppend(readResult, "createStandardFileIsoStep06 result: " + createStandardFileIsoSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!createStandardFileIsoStep06Success) {
                        writeToUiAppend(readResult, "the createStandardFileIsoStep06 was not successful, aborted");
                        //return;
                    }

                    // step 07 write to standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "MIFARE DESFire WriteData to write the content of the NDEF File with NLEN equal to 0000h");
                    responseData = new byte[2];
                    byte[] dataToWriteByte2 = "hello".getBytes(StandardCharsets.UTF_8);
                    boolean writeToStandardFileNdefStep07Success = writeToStandardFileNdefStep07(readResult, FILE_ID_02, dataToWriteByte2, responseData);
                    writeToUiAppend(readResult, "writeToStandardFileNdefStep07 result: " + writeToStandardFileNdefStep07Success + " with response: " + Utils.bytesToHex(responseData));
                    if (!writeToStandardFileNdefStep07Success) {
                        writeToUiAppend(readResult, "the writeToStandardFileNdefStep07 was not successful, aborted");
                        //return;
                    }

/*
see MIFARE DESFire as Type 4 Tag AN11004.pdf pages 33 - 34

8.1 Example of INITIALISED Formatting Procedure

This example shows how the INITIALISED Formatting Procedure (see 6.5.1) may be implemented. As a precondition the
MIFARE DESFire is formatted with the FormatPICC command, and the PICC master key settings values are equal to the default settings.
The example of INITIALISED Formatting Procedure is described below

1. MIFARE DESFire SelectApplication with AID equal to 000000h (PICC level)
Command: 90 5a 00 00 03 00 00 00 00h
Expected Response: 91 00h

2. MIFARE DESFire CreateApplication using the default AID 000001h (see section 6.4.1 for the definition of the
allowed AID values), key settings equal to 0Fh, NumOfKeys equal to 01h, File-ID equal to 10E1h, DF-name equal to D2760000850101
Command: 90 CA 00 00 0E 01 00 00 0F 21 10 E1 D2 76 00 00 85 01 01 00h
Expected Response: 91 00h

3. MIFARE DESFire SelectApplication (Select previously created application)
Command: 90 5A 00 00 03 01 00 00 00h
Expected Response: 91 00h

4. MIFARE DESFire CreateStdDataFile with FileNo equal to 01h (CC File DESFire FID),
ISO FileID equal to E103h, ComSet equal to 00h, AccessRights equal to EEEEh, FileSize bigger equal to 00000Fh
Command: 90 CD 00 00 09 01 03 E1 00 00 E0 0F 00 00 00h
NOTE: There is an error in the command, the Access Rights do have a wrong value ("00 E0" instead of "EE EE"
Expected Response: 91 00h

5. MIFARE DESFire WriteData to write the content of the CC File with CCLEN equal
to 000Fh, Mapping Version equal to 20h, MLe equal to 003Ah, MLc equal to 0034h,
and NDEF File Control TLV equal to: T=04h, L=06h, V=E1 04 (NDEF ISO FID = E104h) 08 00
(NDEF File size = 2048 Bytes) 00 (free read access) 00 (free write access)
Command: 90 3D 00 00 16 01 00 00 00 0F 00 00 00 0F 20 00 3A 00 34 04 06 E1 04 08 00 00 00 00h
Expected Response: 91 00h

6. MIFARE DESFire CreateStdDataFile with FileNo equal to 02h (NDEF File DESFire FID), ISO FileID
equal to E104h, ComSet equal to 00h, ComSet equal to 00h, AccessRights equal to EEE0h, FileSize equal to 000800h (2048 Bytes)
Command: 90 CD 00 00 09 02 04 E1 00 E0 EE 00 08 00 00h
Expected Response: 91 00h

7. MIFARE DESFire WriteData to write the content of the NDEF File with NLEN equal to 0000h, and no NDEF Message
Command: 90 3D 00 00 09 02 00 00 00 02 00 00 00 00 00h
Expected Response: 91 00h

8.2 MIFARE DESFire EV1 GetVersion command using the Wrapping of Native DESFire APDUs

The Card Identification Procedure (see section 2.2) requires the sending of the MIFARE DESFire EV1 GetVersion
command in order to get the Software Major Version and the Software Storage Size. In the example below the
following acronym are used:
XX to indicate a generic byte with no relevant meaning,
SW byte indicating the Software Major Version and
SS indicating the Software Storage code.

The example of MIFARE DESFire EV1 GetVersion command is described below using the wrapping of Native DESFire APDUs:

8. MIFARE DESFire EV1 GetVersion command 1
Command: 90 60 00 00 00h
Expected Response: XX XX XX XX XX XX XX 91 AFh

9. MIFARE DESFire EV1 GetVersion command 2.
The Storage Size code (SS) value indicates the storage size, in particular: 1Ah indicates 8192 bytes,
18h indicates 4096 bytes and 16h indicates 2048 bytes
Command: 90 AF 00 00 00h
Expected Response: XX XX XX SW XX SS XX 91 AFh

10. MIFARE DESFire EV1 GetVersion command 3
Command: 90 AF 00 00 00h
ExpectedResponse:XXXXXXXXXXXXXXXXXXXXXXXXXX9100

 */


                } catch (Exception e) {
                    writeToUiAppend(readResult, "Ex Error with DESFireEV1 + " + e.getMessage());
                }

            }
        });

        btn3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

            }
        });

        btn4.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

            }
        });

        btn5.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

            }
        });

    }


    /**
     * start section for ready to use commands
     */

    private boolean createApplicationIsoDes(TextView logTextView, byte[] applicationIdentifier, byte keySettings, byte numberOfKeys, byte[] applicationIdentifierFileId, byte[] applicationIdentifierDfName, byte[] response) {
        if (logTextView == null) return false;
        if (applicationIdentifier == null) return false;
        if (applicationIdentifier.length != 3) return false;

        // MIFARE DESFire CreateApplication using the default AID 000001h (see section 6.4.1 for the definition of the allowed AID values),
        // key settings equal to 0Fh, NumOfKeys equal to 01h, File-ID equal to 10E1h, DF-name equal to D2760000850101
        // Command: 90 CA 00 00 0E 01 00 00 0F 21 10 E1 D2 76 00 00 85 01 01 00h

        // todo change this is rough code from MIFARE DESFire as Type 4 Tag AN11004.pdf
        /*

         */
        byte[] commandSequence = Utils.hexStringToByteArray("90CA00000E0100000F2110E1D276000085010100"); // this is the command for 0e0e
        // byte[] commandSequence = Utils.hexStringToByteArray("90CA00000E0100000F2110E1D276000085010100"); this is the command in the pdf

        byte createApplicationCommand = (byte) 0xCA;
        PayloadBuilder pb = new PayloadBuilder();
        byte[] commandParameters = pb.createApplicationIso(applicationIdentifier, keySettings, numberOfKeys, applicationIdentifierFileId, applicationIdentifierDfName);
        byte[] wrappedCommand = new byte[0];
        try {
            wrappedCommand = wrapMessage(createApplicationCommand, commandParameters);
        } catch (Exception e) {
            writeToUiAppend(logTextView, "error on running the createApplicationIsoDes command " + e.getMessage());
        }
        writeToUiAppend(logTextView, printData("commandSequence", commandSequence));
        writeToUiAppend(logTextView, printData("command Builder", wrappedCommand));

/*
        // create an application
        byte createApplicationCommand = (byte) 0xca;
        PayloadBuilder pb = new PayloadBuilder();
        byte[] createApplicationParameters = pb.createApplicationIso(applicationIdentifier, keySettings, numberOfKeys, applicationIdentifierFileId, applicationIdentifierDfName);
        writeToUiAppend(logTextView, printData("createApplicationIsoParameters", createApplicationParameters));
        */
        byte[] createApplicationResponse = new byte[0];
        try {
            //createApplicationResponse = isoDep.transceive(commandSequence);
            createApplicationResponse = isoDep.transceive(wrappedCommand);
            //createApplicationResponse = isoDep.transceive(wrapMessage(createApplicationCommand, createApplicationParameters));
            //writeToUiAppend(logTextView, printData("createApplicationIsoResponse", createApplicationResponse));
            System.arraycopy(returnStatusBytes(createApplicationResponse), 0, response, 0, 2);
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (checkResponse(createApplicationResponse)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "createApplicationIso transceive failed: " + e.getMessage());
            return false;
        }
    }

    private boolean selectApplicationIso(TextView logTextView, byte[] applicationIdentifier, byte[] response) {

        // todo change this is rough programming
        byte[] commandSequence = Utils.hexStringToByteArray("905A00000301000000");


        // select application
        byte selectApplicationCommand = (byte) 0x5a;
        byte[] selectApplicationResponse = new byte[0];
        try {
            selectApplicationResponse = isoDep.transceive(commandSequence);
            //selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
            writeToUiAppend(logTextView, printData("selectApplicationResponse", selectApplicationResponse));
            System.arraycopy(returnStatusBytes(selectApplicationResponse), 0, response, 0, 2);
            //System.arraycopy(selectApplicationResponse, 0, response, 0, selectApplicationResponse.length);
            if (checkResponse(selectApplicationResponse)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "selectApplicationDes transceive failed: " + e.getMessage());
            return false;
        }
    }

    private boolean createStandardFileIso(TextView logTextView, int fileNumber, byte[] isoFileId, PayloadBuilder.CommunicationSetting communicationSetting,
                                          int keyRW, int keyCar, int keyR, int keyW, int fileSize, byte[] response) {

        // this code is taken from MIFARE DESFire as Type 4 Tag AN11004.pdf
        // this is raw code with fixed data, todo CHANGE
        /*
        step 4
        MIFARE DESFire CreateStdDataFile with FileNo equal to 01h (CC File DESFire FID),
        ISO FileID equal to E103h, ComSet equal to 00h, AccessRights equal to EEEEh,
        FileSize bigger equal to 00000Fh
        Command: 90 CD 00 00 09 01 03 E1 00 00 E0 0F 00 00 00h
        NOTE: There is an error in the command, the Access Rights do have a wrong value

        step 6
        MIFARE DESFire CreateStdDataFile with FileNo equal to 02h (NDEF File DESFire FID),
        ISO FileID equal to E104h, ComSet equal to 00h, AccessRights equal to EEE0h,
        FileSize equal to 000800h (2048 Bytes)
        Command: 90 CD 00 00 09 02 04 E1 00 E0 EE 00 08 00 00h
         */
        byte[] commandSequence = Utils.hexStringToByteArray("90CD0000090103E100EEEE0F000000");

        byte createApplicationCommand = (byte) 0xCD;
        PayloadBuilder pb = new PayloadBuilder();
        byte[] commandParameters = pb.createStandardFileIso(fileNumber, isoFileId, communicationSetting, keyRW, keyCar, keyR, keyW, fileSize);
        byte[] wrappedCommand = new byte[0];
        try {
            wrappedCommand = wrapMessage(createApplicationCommand, commandParameters);
        } catch (Exception e) {
            writeToUiAppend(logTextView, "error on running the createApplicationIsoDes command " + e.getMessage());
        }
        writeToUiAppend(logTextView, printData("commandSequence", commandSequence));
        writeToUiAppend(logTextView, printData("command Builder", wrappedCommand));



        byte[] createStandardFileResponse = new byte[0];
        try {
            createStandardFileResponse = isoDep.transceive(wrappedCommand);
            //createStandardFileResponse = isoDep.transceive(wrapMessage(createStandardFileCommand, createStandardFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(readResult, printData("createStandardFileResponse", createStandardFileResponse));
        System.arraycopy(returnStatusBytes(createStandardFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createStandardFileResponse", createStandardFileResponse));
        if (checkDuplicateError(createStandardFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean createStandardFileIsoStep6(TextView logTextView, byte fileNumber, byte[] response) {

        // this code is taken from MIFARE DESFire as Type 4 Tag AN11004.pdf
        // this is raw code with fixed data, todo CHANGE
        /*
        step 4
        MIFARE DESFire CreateStdDataFile with FileNo equal to 01h (CC File DESFire FID),
        ISO FileID equal to E103h, ComSet equal to 00h, AccessRights equal to EEEEh,
        FileSize bigger equal to 00000Fh
        Command: 90 CD 00 00 09 01 03 E1 00 00 E0 0F 00 00 00h

        step 6
        MIFARE DESFire CreateStdDataFile with FileNo equal to 02h (NDEF File DESFire FID),
        ISO FileID equal to E104h, ComSet equal to 00h, AccessRights equal to EEE0h,
        FileSize equal to 000800h (2048 Bytes)
        Command: 90 CD 00 00 09 02 04 E1 00 E0 EE 00 08 00 00h
         */
        //byte[] commandSequence =  Utils.hexStringToByteArray("90CD0000090103E10000E00F000000");
        byte[] commandSequence = Utils.hexStringToByteArray("90CD0000090204E100E0EE00080000");
        byte[] createStandardFileResponse = new byte[0];
        try {
            createStandardFileResponse = isoDep.transceive(commandSequence);
            //createStandardFileResponse = isoDep.transceive(wrapMessage(createStandardFileCommand, createStandardFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(readResult, printData("createStandardFileResponse", createStandardFileResponse));
        System.arraycopy(returnStatusBytes(createStandardFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createStandardFileResponse", createStandardFileResponse));
        if (checkDuplicateError(createStandardFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean writeToStandardFileNdef(TextView logTextView, byte fileNumber, byte[] data, byte[] response) {

        /*
        MIFARE DESFire WriteData to write the content of the CC File with CCLEN equal to 000Fh,
        Mapping Version equal to 20h, MLe equal to 003Ah, MLc equal to 0034h,
        and NDEF File Control TLV equal to: T=04h, L=06h, V=E1 04 (NDEF ISO FID = E104h)
        08 00 (NDEF File size = 2048 Bytes) 00 (free read access) 00 (free write access)
        Command: 90 3D 00 00 16 01 00 00 00 0F 00 00 00 0F 20 00 3A 00 34 04 06 E1 04 08 00 00 00 00h
         */
        byte[] commandSequence = Utils.hexStringToByteArray("903D000016010000000F0000000F20003A00340406E1040800000000");
        byte[] writeStandardFileResponse = new byte[0];
        try {
            writeStandardFileResponse = isoDep.transceive(commandSequence);
            //writeStandardFileResponse = isoDep.transceive(wrapMessage(writeStandardFileCommand, writeStandardFileParameters));
            //writeToUiAppend(logTextView, printData("send APDU", wrapMessage(writeStandardFileCommand, writeStandardFileParameters)));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeStandardFileResponse", writeStandardFileResponse));
        System.arraycopy(returnStatusBytes(writeStandardFileResponse), 0, response, 0, 2);
        if (checkResponse(writeStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean writeToStandardFileNdefStep07(TextView logTextView, byte fileNumber, byte[] data, byte[] response) {

        /*
        step 05
        MIFARE DESFire WriteData to write the content of the CC File with CCLEN equal to 000Fh,
        Mapping Version equal to 20h, MLe equal to 003Ah, MLc equal to 0034h,
        and NDEF File Control TLV equal to: T=04h, L=06h, V=E1 04 (NDEF ISO FID = E104h)
        08 00 (NDEF File size = 2048 Bytes) 00 (free read access) 00 (free write access)
        Command: 90 3D 00 00 16 01 00 00 00 0F 00 00 00 0F 20 00 3A 00 34 04 06 E1 04 08 00 00 00 00h

        step 07
        MIFARE DESFire WriteData to write the content of the NDEF File with NLEN equal to 0000h,
        and no NDEF Message
        Command: 90 3D 00 00 09 02 00 00 00 02 00 00 00 00 00h
         */
        //byte[] commandSequence = Utils.hexStringToByteArray("903D000016010000000F0000000F20003A00340406E1040800000000");
        byte[] commandSequence = Utils.hexStringToByteArray("903D00000902000000020000000000");
        byte[] writeStandardFileResponse = new byte[0];
        try {
            writeStandardFileResponse = isoDep.transceive(commandSequence);
            //writeStandardFileResponse = isoDep.transceive(wrapMessage(writeStandardFileCommand, writeStandardFileParameters));
            //writeToUiAppend(logTextView, printData("send APDU", wrapMessage(writeStandardFileCommand, writeStandardFileParameters)));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeStandardFileResponse", writeStandardFileResponse));
        System.arraycopy(returnStatusBytes(writeStandardFileResponse), 0, response, 0, 2);
        if (checkResponse(writeStandardFileResponse)) {
            return true;
        } else {
            return false;
        }

    }




    /**
     * section for authentication with aes keys, copied from DESFireEV1.java
     */

    /**
     * Mutual authentication between PCD and PICC.
     *
     * @param key   the secret key (8 bytes for DES, 16 bytes for 3DES/AES and
     *              24 bytes for 3K3DES)
     * @param keyNo the key number
     * @param type  the cipher
     * @return true for success
     * @throws IOException
     */
    public boolean authenticate(byte[] key, byte keyNo, KeyType type) throws IOException {
        if (!validateKey(key, type)) {
            System.out.println("***DESFireEV1.java authenticate validateKey: " + com.github.skjolber.desfire.ev1.model.command.Utils.getHexString(key));
            throw new IllegalArgumentException();
        }
        if (type != KeyType.AES) {
            // remove version bits from Triple DES keys
            setKeyVersion(key, 0, key.length, (byte) 0x00);
        }

        final byte[] iv0 = type == KeyType.AES ? new byte[16] : new byte[8];
        byte[] apdu;
        byte[] responseAPDU;

        // 1st message exchange
        apdu = new byte[7];
        apdu[0] = (byte) 0x90;
        switch (type) {
            case DES:
            case TDES:
                //apdu[1] = (byte) DESFireEV1.Command.AUTHENTICATE_DES_2K3DES.getCode();
                apdu[1] = (byte) 0x0A;
                break;
            case TKTDES:
                //apdu[1] = (byte) DESFireEV1.Command.AUTHENTICATE_3K3DES.getCode();
                apdu[1] = (byte) 0x1A;
                break;
            case AES:
                //apdu[1] = (byte) DESFireEV1.Command.AUTHENTICATE_AES.getCode();
                apdu[1] = (byte) 0xAA;
                break;
            default:
                assert false : type;
        }
        apdu[4] = 0x01;
        apdu[5] = keyNo;
        //responseAPDU = transmit(apdu);

        writeToUiAppend(readResult, printData("1st message exchange send", apdu));
        responseAPDU = isoDep.transceive(apdu);
        writeToUiAppend(readResult, printData("1st message exchange resp", responseAPDU));
        //this.code = getSW2(responseAPDU);
        //feedback(apdu, responseAPDU);
        //if (getSW2(responseAPDU) != 0xAF) return false;

        //byte[] responseData = getData(responseAPDU);
        byte[] responseData = Arrays.copyOf(responseAPDU, responseAPDU.length - 2);
        // step 3
        //byte[] randB = recv(key, getData(responseAPDU), type, iv0);
        byte[] randB = recv(key, responseData, type, iv0);
        writeToUiAppend(readResult, "step 3");
        writeToUiAppend(readResult, printData("randB", randB));
        writeToUiAppend(readResult, printData("iv0", iv0));

        if (randB == null)
            return false;
        byte[] randBr = rotateLeft(randB);
        writeToUiAppend(readResult, printData("rotate left randB", randB));

        byte[] randA = new byte[randB.length];

        //fillRandom(randA);
        // we are using a static randA
        randA = Utils.hexStringToByteArray("000102030405060708090a0b0c0d0e0f");
        writeToUiAppend(readResult, printData("randA", randA));

        // step 3: encryption
        writeToUiAppend(readResult, "encryption");
        byte[] plaintext = new byte[randA.length + randBr.length];
        System.arraycopy(randA, 0, plaintext, 0, randA.length);
        System.arraycopy(randBr, 0, plaintext, randA.length, randBr.length);
        writeToUiAppend(readResult, printData("plaintext randA|randB", plaintext));
        byte[] iv1 = Arrays.copyOfRange(responseData,
                responseData.length - iv0.length, responseData.length);
        writeToUiAppend(readResult, printData("iv1", iv1));
        byte[] ciphertext = send(key, plaintext, type, iv1);
        if (ciphertext == null)
            return false;
        writeToUiAppend(readResult, printData("ciphertext", ciphertext));
        // 2nd message exchange
        writeToUiAppend(readResult, "2nd message exchange");
        apdu = new byte[5 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = (byte) 0xAF;
        apdu[4] = (byte) ciphertext.length;
        System.arraycopy(ciphertext, 0, apdu, 5, ciphertext.length);
        //responseAPDU = transmit(apdu);
        responseAPDU = isoDep.transceive(apdu);
        writeToUiAppend(readResult, printData("2nd message exchange send", apdu));
        writeToUiAppend(readResult, printData("2nd message exchange resp", responseAPDU));
        //this.code = getSW2(responseAPDU);
        //feedback(apdu, responseAPDU);
        //if (getSW2(responseAPDU) != 0x00) return false;

        // step 5
        byte[] iv2 = Arrays.copyOfRange(ciphertext,
                ciphertext.length - iv0.length, ciphertext.length);
        writeToUiAppend(readResult, printData("iv2", iv2));
        byte[] responseData2 = Arrays.copyOf(responseAPDU, responseAPDU.length - 2);
        writeToUiAppend(readResult, printData("responseData2", responseData2));
        byte[] randAr = recv(key, responseData2, type, iv2);
        writeToUiAppend(readResult, printData("randAr", randAr));
        //byte[] randAr = recv(key, getData(responseAPDU), type, iv2);

        if (randAr == null)
            return false;
        byte[] randAr2 = rotateLeft(randA);
        writeToUiAppend(readResult, printData("rotate left randAr", randAr2));
        for (int i = 0; i < randAr2.length; i++)
            if (randAr[i] != randAr2[i])
                return false;
        writeToUiAppend(readResult, "compare both randA values");
        writeToUiAppend(readResult, printData("randA Original", randA));
        writeToUiAppend(readResult, printData("randA Or. rot ", randAr2));
        writeToUiAppend(readResult, printData("randAr Receivt", randAr));

        // step 6
        byte[] skey = generateSessionKey(randA, randB, type);
        writeToUiAppend(readResult, printData("sessionKey", skey));

        //this.ktype = type;
        //this.kno = keyNo;
        //this.iv = iv0;
        //this.skey = skey;

        return true;
    }

    /**
     * DES/3DES mode of operation.
     */
    private enum DESMode {
        SEND_MODE,
        RECEIVE_MODE;
    }

    // Receiving data that needs decryption.
    private static byte[] recv(byte[] key, byte[] data, KeyType type, byte[] iv) {
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
    private static byte[] send(byte[] key, byte[] data, KeyType type, byte[] iv) {
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

    /**
     * Generate the session key using the random A generated by the PICC and
     * the random B generated by the PCD.
     *
     * @param randA the random number A
     * @param randB the random number B
     * @param type  the type of key
     * @return the session key
     */
    private static byte[] generateSessionKey(byte[] randA, byte[] randB, KeyType type) {
        byte[] skey = null;

        switch (type) {
            case DES:
                skey = new byte[8];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                break;
            case TDES:
                skey = new byte[16];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                System.arraycopy(randA, 4, skey, 8, 4);
                System.arraycopy(randB, 4, skey, 12, 4);
                break;
            case TKTDES:
                skey = new byte[24];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                System.arraycopy(randA, 6, skey, 8, 4);
                System.arraycopy(randB, 6, skey, 12, 4);
                System.arraycopy(randA, 12, skey, 16, 4);
                System.arraycopy(randB, 12, skey, 20, 4);
                break;
            case AES:
                skey = new byte[16];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                System.arraycopy(randA, 12, skey, 8, 4);
                System.arraycopy(randB, 12, skey, 12, 4);
                break;
            default:
                assert false : type;  // never reached
        }

        return skey;
    }

    /**
     * section for authentication with aes keys
     */

    // if verbose = true all steps are printed out
    private boolean authenticateApplicationAes(TextView logTextView, byte keyId, byte[] key, boolean verbose, byte[] response) {
        try {
            writeToUiAppend(logTextView, "authenticateApplicationAes for keyId " + keyId + " and key " + Utils.bytesToHex(key));
            // do DES auth
            //String getChallengeCommand = "901a0000010000";
            //String getChallengeCommand = "9084000000"; // IsoGetChallenge

            //byte[] getChallengeResponse = nfcA.transceive(Utils.hexStringToByteArray(getChallengeCommand));
            //byte[] getChallengeResponse = nfcA.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) 0x01} ));
            byte[] getChallengeResponse = isoDep.transceive(wrapMessage((byte) 0xaa, new byte[]{(byte) (keyId & 0xFF)}));
            if (verbose)
                writeToUiAppend(logTextView, printData("getChallengeResponse", getChallengeResponse)); // this 16 bytes long
            // cf5e0ee09862d90391af
            // 91 af at the end shows there is more data

            byte[] challenge = Arrays.copyOf(getChallengeResponse, getChallengeResponse.length - 2);
            if (verbose) writeToUiAppend(logTextView, printData("challengeResponse", challenge));

            // Of course the rndA shall be a random number,
            // but we will use a constant number to make the example easier.
            byte[] rndA = Utils.hexStringToByteArray("000102030405060708090a0b0c0d0e0f");
            if (verbose) writeToUiAppend(logTextView, printData("rndA", rndA));

            // This is the default key for a blank AESFire card.
            // defaultKey = 16 byte array = [0x00, ..., 0x00]
            //byte[] defaultAESKey = Utils.hexStringToByteArray("00000000000000000000000000000000");
            byte[] defaultAESKey = key.clone();
            byte[] IV = new byte[16];

            // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
            byte[] rndB = decryptAes(challenge, defaultAESKey, IV);
            if (verbose) writeToUiAppend(logTextView, printData("rndB", rndB));
            // Rotate left the rndB byte[] leftRotatedRndB = rotateLeft(rndB);
            byte[] leftRotatedRndB = rotateLeft(rndB);
            if (verbose)
                writeToUiAppend(logTextView, printData("leftRotatedRndB", leftRotatedRndB));
            // Concatenate the RndA and rotated RndB byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            if (verbose) writeToUiAppend(logTextView, printData("rndA_rndB", rndA_rndB));

            // Encrypt the bytes of the last step to get the challenge answer byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
            IV = challenge;
            byte[] challengeAnswer = encryptAes(rndA_rndB, defaultAESKey, IV);
            IV = Arrays.copyOfRange(challengeAnswer, 16, 32);
            if (verbose) {
                writeToUiAppend(logTextView, printData("challengeAnswer", challengeAnswer));
                writeToUiAppend(logTextView, printData("new IV         ", IV));
            }

                /*
                    Build and send APDU with the answer. Basically wrap the challenge answer in the APDU.
                    The total size of apdu (for this scenario) is 22 bytes:
                    > 0x90 0xAF 0x00 0x00 0x10 [16 bytes challenge answer] 0x00
                */
            byte[] challengeAnswerAPDU = new byte[38]; // old 22
            challengeAnswerAPDU[0] = (byte) 0x90; // CLS
            challengeAnswerAPDU[1] = (byte) 0xAF; // INS
            challengeAnswerAPDU[2] = (byte) 0x00; // p1
            challengeAnswerAPDU[3] = (byte) 0x00; // p2
            challengeAnswerAPDU[4] = (byte) 0x20; // data length: 32 bytes
            challengeAnswerAPDU[challengeAnswerAPDU.length - 1] = (byte) 0x00;
            System.arraycopy(challengeAnswer, 0, challengeAnswerAPDU, 5, challengeAnswer.length);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerAPDU", challengeAnswerAPDU));

            /*
             * Sending the APDU containing the challenge answer.
             * It is expected to be return 18 bytes [rndA from the Card] + 9100
             */
            byte[] challengeAnswerResponse = isoDep.transceive(challengeAnswerAPDU);
            // response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResponse", challengeAnswerResponse));
            byte[] challengeAnswerResp = Arrays.copyOf(challengeAnswerResponse, getChallengeResponse.length - 2);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResp", challengeAnswerResp));

            /*
             * At this point, the challenge was processed by the card. The card decrypted the
             * rndA rotated it and sent it back.
             * Now we need to check if the RndA sent by the Card is valid.
             */// encrypted rndA from Card, returned in the last step byte[] encryptedRndAFromCard = response.getData();

            // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            //byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            byte[] rotatedRndAFromCard = decryptAes(challengeAnswerResp, defaultAESKey, IV);
            if (verbose)
                writeToUiAppend(logTextView, printData("rotatedRndAFromCard", rotatedRndAFromCard));

            // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            if (verbose) writeToUiAppend(logTextView, printData("rndAFromCard", rndAFromCard));
            writeToUiAppend(logTextView, "********** AUTH RESULT **********");
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (Arrays.equals(rndA, rndAFromCard)) {
                writeToUiAppend(logTextView, "Authenticated");

                // generate the session key
                //skey = generateSessionKey(rndA, rndB, KeyType.AES);


                // own vars
                ivOwn = new byte[16]; // AES IV is 16 bytes long
                skeyOwn = generateSessionKey(rndA, rndB, KeyType.AES);
                writeToUiAppend(logTextView, printData("## ivOwn ##", ivOwn));
                writeToUiAppend(logTextView, printData("## session key ##", skeyOwn));
                return true;
            } else {
                writeToUiAppend(logTextView, "Authentication failed");
                skey = null;
                return false;
                //System.err.println(" ### Authentication failed. ### ");
                //log("rndA:" + toHexString(rndA) + ", rndA from Card: " + toHexString(rndAFromCard));
            }
            //writeToUiAppend(logTextView, "********** AUTH RESULT END **********");
            //return false;
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "authenticateApplicationAes transceive failed: " + e.getMessage());
            writeToUiAppend(logTextView, "authenticateApplicationAes transceive failed: " + Arrays.toString(e.getStackTrace()));
        }
        //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
        return false;

        // todo set global IV to zero's

    }


    /**
     * section for authentication with DES
     */

    // if verbose = true all steps are printed out
    private boolean authenticateApplicationDes(TextView logTextView, byte keyId, byte[] key, boolean verbose, byte[] response) {
        try {
            writeToUiAppend(logTextView, "authenticateApplicationDes for keyId " + keyId + " and key " + Utils.bytesToHex(key));
            // do DES auth
            //String getChallengeCommand = "901a0000010000";
            //String getChallengeCommand = "9084000000"; // IsoGetChallenge

            //byte[] getChallengeResponse = nfcA.transceive(Utils.hexStringToByteArray(getChallengeCommand));
            //byte[] getChallengeResponse = nfcA.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) 0x01} ));
            byte[] getChallengeResponse = isoDep.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) (keyId & 0xFF)}));
            if (verbose)
                writeToUiAppend(logTextView, printData("getChallengeResponse", getChallengeResponse));
            // cf5e0ee09862d90391af
            // 91 af at the end shows there is more data

            byte[] challenge = Arrays.copyOf(getChallengeResponse, getChallengeResponse.length - 2);
            if (verbose) writeToUiAppend(logTextView, printData("challengeResponse", challenge));

            // Of course the rndA shall be a random number,
            // but we will use a constant number to make the example easier.
            byte[] rndA = Utils.hexStringToByteArray("0001020304050607");
            if (verbose) writeToUiAppend(logTextView, printData("rndA", rndA));

            // This is the default key for a blank DESFire card.
            // defaultKey = 8 byte array = [0x00, ..., 0x00]
            //byte[] defaultDESKey = Utils.hexStringToByteArray("0000000000000000");
            byte[] defaultDESKey = key.clone();
            byte[] IV = new byte[8];

            // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
            byte[] rndB = decrypt(challenge, defaultDESKey, IV);
            if (verbose) writeToUiAppend(logTextView, printData("rndB", rndB));
            // Rotate left the rndB byte[] leftRotatedRndB = rotateLeft(rndB);
            byte[] leftRotatedRndB = rotateLeft(rndB);
            if (verbose)
                writeToUiAppend(logTextView, printData("leftRotatedRndB", leftRotatedRndB));
            // Concatenate the RndA and rotated RndB byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            if (verbose) writeToUiAppend(logTextView, printData("rndA_rndB", rndA_rndB));

            // Encrypt the bytes of the last step to get the challenge answer byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
            IV = challenge;
            byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswer", challengeAnswer));

            IV = Arrays.copyOfRange(challengeAnswer, 8, 16);
                /*
                    Build and send APDU with the answer. Basically wrap the challenge answer in the APDU.
                    The total size of apdu (for this scenario) is 22 bytes:
                    > 0x90 0xAF 0x00 0x00 0x10 [16 bytes challenge answer] 0x00
                */
            byte[] challengeAnswerAPDU = new byte[22];
            challengeAnswerAPDU[0] = (byte) 0x90; // CLS
            challengeAnswerAPDU[1] = (byte) 0xAF; // INS
            challengeAnswerAPDU[2] = (byte) 0x00; // p1
            challengeAnswerAPDU[3] = (byte) 0x00; // p2
            challengeAnswerAPDU[4] = (byte) 0x10; // data length: 16 bytes
            challengeAnswerAPDU[challengeAnswerAPDU.length - 1] = (byte) 0x00;
            System.arraycopy(challengeAnswer, 0, challengeAnswerAPDU, 5, challengeAnswer.length);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerAPDU", challengeAnswerAPDU));

            /*
             * Sending the APDU containing the challenge answer.
             * It is expected to be return 10 bytes [rndA from the Card] + 9100
             */
            byte[] challengeAnswerResponse = isoDep.transceive(challengeAnswerAPDU);
            // response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResponse", challengeAnswerResponse));
            byte[] challengeAnswerResp = Arrays.copyOf(challengeAnswerResponse, getChallengeResponse.length - 2);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResp", challengeAnswerResp));

            /*
             * At this point, the challenge was processed by the card. The card decrypted the
             * rndA rotated it and sent it back.
             * Now we need to check if the RndA sent by the Card is valid.
             */// encrypted rndA from Card, returned in the last step byte[] encryptedRndAFromCard = response.getData();

            // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            //byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            byte[] rotatedRndAFromCard = decrypt(challengeAnswerResp, defaultDESKey, IV);
            if (verbose)
                writeToUiAppend(logTextView, printData("rotatedRndAFromCard", rotatedRndAFromCard));

            // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            if (verbose) writeToUiAppend(logTextView, printData("rndAFromCard", rndAFromCard));
            writeToUiAppend(logTextView, "********** AUTH RESULT **********");
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (Arrays.equals(rndA, rndAFromCard)) {
                writeToUiAppend(logTextView, "Authenticated");
                return true;
            } else {
                writeToUiAppend(logTextView, "Authentication failed");
                return false;
                //System.err.println(" ### Authentication failed. ### ");
                //log("rndA:" + toHexString(rndA) + ", rndA from Card: " + toHexString(rndAFromCard));
            }
            //writeToUiAppend(logTextView, "********** AUTH RESULT END **********");
            //return false;
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "authenticateApplicationDes transceive failed: " + e.getMessage());
            writeToUiAppend(logTextView, "authenticateApplicationDes transceive failed: " + Arrays.toString(e.getStackTrace()));
        }
        //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
        return false;
    }


    /**
     * section for application handling
     */

    private boolean createApplicationDes(TextView logTextView, byte[] applicationIdentifier, byte numberOfKeys, byte[] response) {
        if (logTextView == null) return false;
        if (applicationIdentifier == null) return false;
        if (applicationIdentifier.length != 3) return false;

        // create an application
        writeToUiAppend(logTextView, "create the application " + Utils.bytesToHex(applicationIdentifier));
        byte createApplicationCommand = (byte) 0xca;
        byte applicationMasterKeySettings = (byte) 0x0f;
        byte[] createApplicationParameters = new byte[5];
        System.arraycopy(applicationIdentifier, 0, createApplicationParameters, 0, applicationIdentifier.length);
        createApplicationParameters[3] = applicationMasterKeySettings;
        createApplicationParameters[4] = numberOfKeys;
        writeToUiAppend(logTextView, printData("createApplicationParameters", createApplicationParameters));
        byte[] createApplicationResponse = new byte[0];
        try {
            createApplicationResponse = isoDep.transceive(wrapMessage(createApplicationCommand, createApplicationParameters));
            writeToUiAppend(logTextView, printData("createApplicationResponse", createApplicationResponse));
            System.arraycopy(returnStatusBytes(createApplicationResponse), 0, response, 0, 2);
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (checkResponse(createApplicationResponse)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "createApplicationAes transceive failed: " + e.getMessage());
            return false;
        }
    }



    private boolean createApplicationAes(TextView logTextView, byte[] applicationIdentifier, byte numberOfKeys, byte[] response) {
        if (logTextView == null) return false;
        if (applicationIdentifier == null) return false;
        if (applicationIdentifier.length != 3) return false;
        if ((numberOfKeys < 1) || (numberOfKeys > 15)) return false;

        // create an application
        writeToUiAppend(logTextView, "create the application " + Utils.bytesToHex(applicationIdentifier));
        byte createApplicationCommand = (byte) 0xca;
        byte applicationMasterKeySettings = (byte) 0x0f;
        byte[] createApplicationParameters = new byte[5];
        System.arraycopy(applicationIdentifier, 0, createApplicationParameters, 0, applicationIdentifier.length);
        createApplicationParameters[3] = applicationMasterKeySettings;
        createApplicationParameters[4] = numberOfKeys;
        writeToUiAppend(logTextView, printData("createApplicationParameters", createApplicationParameters));
        byte[] createApplicationResponse = new byte[0];
        try {
            createApplicationResponse = isoDep.transceive(wrapMessage(createApplicationCommand, createApplicationParameters));
            writeToUiAppend(logTextView, printData("createApplicationResponse", createApplicationResponse));
            System.arraycopy(returnStatusBytes(createApplicationResponse), 0, response, 0, 2);
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (checkResponse(createApplicationResponse)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "createApplicationDes transceive failed: " + e.getMessage());
            return false;
        }
    }

    private boolean selectApplicationDes(TextView logTextView, byte[] applicationIdentifier, byte[] response) {
        // select application
        byte selectApplicationCommand = (byte) 0x5a;
        byte[] selectApplicationResponse = new byte[0];
        try {
            selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
            writeToUiAppend(logTextView, printData("selectApplicationResponse", selectApplicationResponse));
            System.arraycopy(returnStatusBytes(selectApplicationResponse), 0, response, 0, 2);
            //System.arraycopy(selectApplicationResponse, 0, response, 0, selectApplicationResponse.length);
            if (checkResponse(selectApplicationResponse)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "selectApplicationDes transceive failed: " + e.getMessage());
            return false;
        }
    }



    private byte[] getKeySettings(TextView logTextView, byte[] response) {
        // getKeySettingsResponse length: 4 data: 0f 01 9100
        //                                        0f = key settings
        //                                           01 = max number of keys
        // get master key settings
        byte getKeySettingsCommand = (byte) 0x45;
        byte[] getKeySettingsResponse = new byte[0];
        try {
            getKeySettingsResponse = isoDep.transceive(wrapMessage(getKeySettingsCommand, null));
            writeToUiAppend(logTextView, printData("getKeySettingsResponse", getKeySettingsResponse));
            System.arraycopy(returnStatusBytes(getKeySettingsResponse), 0, response, 0, 2);
            return getKeySettingsResponse;
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * section for standard files
     */




    private boolean createStandardFile(TextView logTextView, byte fileNumber, byte[] response) {
        // we create a standard file within the selected application
        byte createStandardFileCommand = (byte) 0xcd;
        // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
        byte commSettingsByte = 0; // plain communication without any encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
        byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
                /*
                There are four different Access Rights (2 bytes for each file) stored for each file within
                each application:
                - Read Access
                - Write Access
                - Read&Write Access
                - ChangeAccessRights
                 */
        // here we are using key 1 for read and key2 for write access access, key0 has read&write access + change rights !
        byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) 0x12; // Read Access & Write Access // read with key 1, write with key 2
        byte[] fileSize = new byte[]{(byte) 0x20, (byte) 0xf00, (byte) 0x00}; // 32 bytes
        byte[] createStandardFileParameters = new byte[7];
        createStandardFileParameters[0] = fileNumber;
        createStandardFileParameters[1] = commSettingsByte;
        createStandardFileParameters[2] = accessRightsRwCar;
        createStandardFileParameters[3] = accessRightsRW;
        System.arraycopy(fileSize, 0, createStandardFileParameters, 4, 3);
        writeToUiAppend(readResult, printData("createStandardFileParameters", createStandardFileParameters));
        byte[] createStandardFileResponse = new byte[0];
        try {
            createStandardFileResponse = isoDep.transceive(wrapMessage(createStandardFileCommand, createStandardFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(readResult, printData("createStandardFileResponse", createStandardFileResponse));
        System.arraycopy(returnStatusBytes(createStandardFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createStandardFileResponse", createStandardFileResponse));
        if (checkDuplicateError(createStandardFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean createStandardFileAes(TextView logTextView, byte fileNumber, byte[] response) {
        // we create a standard file within the selected application
        byte createStandardFileCommand = (byte) 0xcd;
        // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
        byte commSettingsByte = (byte) 0x03; // encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
        byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
                /*
                There are four different Access Rights (2 bytes for each file) stored for each file within
                each application:
                - Read Access
                - Write Access
                - Read&Write Access
                - ChangeAccessRights
                 */
        // here we are using key 1 for read and key2 for write access access, key0 has read&write access + change rights !
        byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) 0x12; // Read Access & Write Access // read with key 1, write with key 2

        // DO NOT EXTEND THE FILESIZE > 28 bytes, that will crash the write method because the CRC is appended
        // if you do have more data to write you have to chunk them, n0t supported here
        //byte[] fileSize = new byte[]{(byte) 0x20, (byte) 0xf00, (byte) 0x00}; // 32 bytes
        byte[] fileSize = new byte[]{(byte) 0x1c, (byte) 0x00, (byte) 0x00}; // 28 bytes

        byte[] createStandardFileParameters = new byte[7];
        createStandardFileParameters[0] = fileNumber;
        createStandardFileParameters[1] = commSettingsByte;
        createStandardFileParameters[2] = accessRightsRwCar;
        createStandardFileParameters[3] = accessRightsRW;
        System.arraycopy(fileSize, 0, createStandardFileParameters, 4, 3);
        writeToUiAppend(readResult, printData("createStandardFileParameters", createStandardFileParameters));
        byte[] createStandardFileResponse = new byte[0];
        try {
            createStandardFileResponse = isoDep.transceive(wrapMessage(createStandardFileCommand, createStandardFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(readResult, printData("createStandardFileResponse", createStandardFileResponse));
        System.arraycopy(returnStatusBytes(createStandardFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createStandardFileResponse", createStandardFileResponse));
        if (checkDuplicateError(createStandardFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean createStandardFileAes(TextView logTextView, int fileNumber, int fileSize, PayloadBuilder.CommunicationSetting communicationSetting , byte[] response) {
        // we create a standard file within the selected application
        byte createStandardFileCommand = (byte) 0xcd;
        PayloadBuilder pb = new PayloadBuilder();
        byte[] createStandardFileParameters = pb.createStandardFileMax70(fileNumber, communicationSetting,
                0, 0, 1, 2, fileSize);

        // DO NOT EXTEND THE FILESIZE > 28 bytes, that will crash the write method because the CRC is appended
        // if you do have more data to write you have to chunk them, not supported here
        writeToUiAppend(readResult, printData("createStandardFileParameters", createStandardFileParameters));
        byte[] createStandardFileResponse = new byte[0];
        try {
            createStandardFileResponse = isoDep.transceive(wrapMessage(createStandardFileCommand, createStandardFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(readResult, printData("createStandardFileResponse", createStandardFileResponse));
        System.arraycopy(returnStatusBytes(createStandardFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createStandardFileResponse", createStandardFileResponse));
        if (checkDuplicateError(createStandardFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private byte[] readFromStandardFile(TextView logTextView, byte fileNumber, byte[] response) {
        // we read from a standard file within the selected application

        // now read from file
        byte readStandardFileCommand = (byte) 0xbd;
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // no offset, read from the beginning
        byte[] length = new byte[]{(byte) 0x20, (byte) 0x00, (byte) 0x00}; // 32 bytes
        byte[] readStandardFileParameters = new byte[7];
        readStandardFileParameters[0] = fileNumber;
        System.arraycopy(offset, 0, readStandardFileParameters, 1, 3);
        System.arraycopy(length, 0, readStandardFileParameters, 4, 3);
        writeToUiAppend(readResult, printData("readStandardFileParameters", readStandardFileParameters));
        byte[] readStandardFileResponse = new byte[0];
        try {
            readStandardFileResponse = isoDep.transceive(wrapMessage(readStandardFileCommand, readStandardFileParameters));
            writeToUiAppend(logTextView, printData("send APDU", wrapMessage(readStandardFileCommand, readStandardFileParameters)));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("readStandardFileResponse", readStandardFileResponse));
        System.arraycopy(returnStatusBytes(readStandardFileResponse), 0, response, 0, 2);
        return Arrays.copyOf(readStandardFileResponse, readStandardFileResponse.length - 2);
    }

    private byte[] readFromStandardFileExt(TextView logTextView, int fileNumber, int fileLength, byte[] response) {
        // we read from a standard file within the selected application

        // now read from file
        byte readStandardFileCommand = (byte) 0xbd;
        PayloadBuilder pb = new PayloadBuilder();
        byte[] readStandardFileParameters = pb.readFromStandardFile(fileNumber, 0, fileLength);
        writeToUiAppend(readResult, printData("readStandardFileParameters", readStandardFileParameters));

        // should I leave out the last/trailing 00 from the command for transmit chain ?
        //readStandardFileParameters = Arrays.copyOf(readStandardFileParameters, readStandardFileParameters.length - 1);
        // writeStandardFileParameters length: 19 data: 07000000200000546865206c617a7920646f67
        byte[] readStandardFileResponse = new byte[0];
        try {
            byte[] fullWrappedApdu = wrapMessage(readStandardFileCommand, readStandardFileParameters);

            // at this point I using a special send command to allow framing
            readStandardFileResponse = transmitChain(fullWrappedApdu);

            //readStandardFileResponse = isoDep.transceive(f);
            writeToUiAppend(logTextView, printData("send APDU", wrapMessage(readStandardFileCommand, readStandardFileParameters)));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("readStandardFileResponse", readStandardFileResponse));
        System.arraycopy(new byte[]{(byte) 0x91, (byte) 0x00}, 0, response, 0, 2);
        //return Arrays.copyOf(readStandardFileResponse, readStandardFileResponse.length - 2);
        return Arrays.copyOf(readStandardFileResponse, fileLength);
    }

    private byte[] readFromStandardFileAes(TextView logTextView, byte fileNumber, byte[] response, Cryp cryp, int lengthInt) {
        // we read from a standard file within the selected application

        // now read from file
        byte readStandardFileCommand = (byte) 0xbd;
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // no offset, read from the beginning
        // todo work on this with intToByteLsb
        byte[] length = new byte[]{(byte) 0x20, (byte) 0x00, (byte) 0x00}; // 32 bytes
        byte[] readStandardFileParameters = new byte[7];
        readStandardFileParameters[0] = fileNumber;
        System.arraycopy(offset, 0, readStandardFileParameters, 1, 3);
        System.arraycopy(length, 0, readStandardFileParameters, 4, 3);
        writeToUiAppend(readResult, printData("readStandardFileParameters", readStandardFileParameters));
        byte[] readStandardFileResponse = new byte[0];
        byte[] wrappedApdu;
        try {
            wrappedApdu = wrapMessage(readStandardFileCommand, readStandardFileParameters);
            readStandardFileResponse = isoDep.transceive(wrappedApdu);
            writeToUiAppend(logTextView, printData("send APDU", wrappedApdu));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("readStandardFileResponse", readStandardFileResponse));
        System.arraycopy(returnStatusBytes(readStandardFileResponse), 0, response, 0, 2);
        //byte[] responseWithoutStatus = Arrays.copyOf(readStandardFileResponse, readStandardFileResponse.length - 2);
        // first we need to update the IV with the apduCommand
        cryp.preprocessPlain(wrappedApdu);
        // now we can decrypt the received data
        byte[] decryptedResponse = cryp.postprocessEnciphered(readStandardFileResponse, lengthInt); // takes the complete response
        if (decryptedResponse == null) System.arraycopy(new byte[2], 0, response, 0, 2);
        return decryptedResponse;
    }

    private byte[] readFromStandardFileAesMax70(TextView logTextView, int fileNumber, int fileSize, byte[] response, Cryp cryp) {
        // we read from a standard file within the selected application

        // now read from file
        byte readStandardFileCommand = (byte) 0xbd;
        PayloadBuilder pb = new PayloadBuilder();
        byte[] readStandardFileParameters = pb.readFromStandardFile(fileNumber, 0, fileSize);
        writeToUiAppend(readResult, printData("readStandardFileParameters", readStandardFileParameters));
        byte[] readStandardFileResponse = new byte[0];
        byte[] wrappedApdu;
        try {
            wrappedApdu = wrapMessage(readStandardFileCommand, readStandardFileParameters);
            readStandardFileResponse = isoDep.transceive(wrappedApdu);
            writeToUiAppend(logTextView, printData("send APDU", wrappedApdu));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "transceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("readStandardFileResponse", readStandardFileResponse));
        System.arraycopy(returnStatusBytes(readStandardFileResponse), 0, response, 0, 2);
        //byte[] responseWithoutStatus = Arrays.copyOf(readStandardFileResponse, readStandardFileResponse.length - 2);
        // first we need to update the IV with the apduCommand
        cryp.preprocessPlain(wrappedApdu);
        // now we can decrypt the received data
        byte[] decryptedResponse = cryp.postprocessEnciphered(readStandardFileResponse, fileSize); // takes the complete response
        if (decryptedResponse == null) System.arraycopy(new byte[2], 0, response, 0, 2);
        return decryptedResponse;
    }



    // note: we don't need to commit any write on Standard Files
    private boolean writeToStandardFile(TextView logTextView, byte fileNumber, byte[] data, byte[] response) {
        // some sanity checks to avoid any issues
        if (fileNumber < (byte) 0x00) return false;
        if (fileNumber > (byte) 0x0A) return false;
        if (data == null) return false;
        if (data.length == 0) return false;
        if (data.length > 32) return false;

        // write to file
        byte writeStandardFileCommand = (byte) 0x3d;
        int numberOfBytes = data.length;
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // no offset
        // todo use intToBytesLsb
        byte[] length = new byte[]{(byte) (numberOfBytes & 0xFF), (byte) 0xf00, (byte) 0x00}; // 32 bytes
        byte[] writeStandardFileParameters = new byte[(7 + data.length)]; // if encrypted we need to append the CRC
        writeStandardFileParameters[0] = fileNumber;
        System.arraycopy(offset, 0, writeStandardFileParameters, 1, 3);
        System.arraycopy(length, 0, writeStandardFileParameters, 4, 3);
        System.arraycopy(data, 0, writeStandardFileParameters, 7, data.length);

        writeToUiAppend(logTextView, printData("writeStandardFileParameters", writeStandardFileParameters));
        // writeStandardFileParameters length: 19 data: 07000000200000546865206c617a7920646f67
        byte[] writeStandardFileResponse = new byte[0];
        try {
            writeStandardFileResponse = isoDep.transceive(wrapMessage(writeStandardFileCommand, writeStandardFileParameters));
            writeToUiAppend(logTextView, printData("send APDU", wrapMessage(writeStandardFileCommand, writeStandardFileParameters)));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeStandardFileResponse", writeStandardFileResponse));
        System.arraycopy(returnStatusBytes(writeStandardFileResponse), 0, response, 0, 2);
        if (checkResponse(writeStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean writeToStandardFileExt(TextView logTextView, int fileNumber, byte[] data, byte[] response) {
        // some sanity checks to avoid any issues
        if (fileNumber < (byte) 0x00) return false;
        if (fileNumber > (byte) 0x0A) return false;
        if (data == null) return false;
        if (data.length == 0) return false;
        if (data.length > 70) return false;

        // write to file
        byte writeStandardFileCommand = (byte) 0x3d;
        PayloadBuilder pb = new PayloadBuilder();
        byte[] writeStandardFileParameters = pb.writeToStandardFileMax70(fileNumber, data);
        writeToUiAppend(logTextView, printData("writeStandardFileParameters", writeStandardFileParameters));
        // writeStandardFileParameters length: 19 data: 07000000200000546865206c617a7920646f67
        byte[] writeStandardFileResponse = new byte[0];
        try {
            byte[] fullWrappedApdu = wrapMessage(writeStandardFileCommand, writeStandardFileParameters);
            // should I leave out the last/trailing 00 from the command for transmit chain ?, yes !
            fullWrappedApdu = Arrays.copyOf(fullWrappedApdu, fullWrappedApdu.length - 1);

            // at this point I using a special send command to allow framing
            writeStandardFileResponse = transmitChain(fullWrappedApdu);

            //writeStandardFileResponse = isoDep.transceive(wrapMessage(writeStandardFileCommand, writeStandardFileParameters));
            writeToUiAppend(logTextView, printData("send APDU", fullWrappedApdu));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeStandardFileResponse", writeStandardFileResponse));
        System.arraycopy(returnStatusBytes(writeStandardFileResponse), 0, response, 0, 2);
        if (checkResponse(writeStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean writeToStandardFileAes(TextView logTextView, byte fileNumber, byte[] data, byte[] response, Cryp cryp) {
        // some sanity checks to avoid any issues
        if (fileNumber < (byte) 0x00) return false;
        if (fileNumber > (byte) 0x0A) return false;
        if (data == null) return false;
        if (data.length == 0) return false;
        if (data.length > 28) return false; // DO NOT EXTEND THIS

        // write to file
        byte writeStandardFileCommand = (byte) 0x3d;
        int numberOfBytes = data.length;
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // no offset
        // todo use intToBytesLsb
        byte[] length = new byte[]{(byte) (numberOfBytes & 0xFF), (byte) 0xf00, (byte) 0x00}; // 32 bytes
        byte[] writeStandardFileParameters = new byte[(7 + data.length)]; // if encrypted we need to append the CRC
        writeStandardFileParameters[0] = fileNumber;
        System.arraycopy(offset, 0, writeStandardFileParameters, 1, 3);
        System.arraycopy(length, 0, writeStandardFileParameters, 4, 3);
        System.arraycopy(data, 0, writeStandardFileParameters, 7, data.length);

        writeToUiAppend(logTextView, printData("writeStandardFileParameters", writeStandardFileParameters));
        // writeStandardFileParameters length: 19 data: 07000000200000546865206c617a7920646f67
        byte[] writeStandardFileResponse = new byte[0];
        byte[] wrappedApdu;
        try {
            wrappedApdu = wrapMessage(writeStandardFileCommand, writeStandardFileParameters);

            // step 1 Desfire line 2001 write
            // fullApdu = preprocess(fullApdu, 7, cs);  // 7 = 1+3+3 (keyNo+off+len)
            // step 2 Desfire line 1439
            // private byte[] preprocess(byte[] apdu, int offset, DesfireFileCommunicationSettings commSett) {
            // line 1454: case ENCIPHERED: return preprocessEnciphered(apdu, offset);
            // step 3 Desfire line 1506
            // private byte[] preprocessEnciphered(byte[] apdu, int offset) {
            // step 4 Desfire line 1507
            // byte[] ciphertext = encryptApdu(apdu, offset, skey, iv, ktype);
            // step 5 Desfire line 1760
            // private static byte[] encryptApdu(byte[] apdu, int offset, byte[] sessionKey, byte[] iv, KeyType type) {
            // step 6 Desfire line 1776
            // crc = calculateApduCRC32C(apdu);
            // step 7 line 1737
            // private static byte[] calculateApduCRC32C(byte[] apdu) {
// btn
// ### write fullAPDU 1 length: 37 data: 903d00001f010000001800006162636465666768696a6b6c6d6e6f70717273747576777800
// ### write fullAPDU 2 length: 45 data: 903d0000270100000018000044c301ee90aef1a35377a91a053bbc51161fdc6f4c70d69b4ffed9ad760f701a00
// this method                                      | difference is filenumber
//   wrapped plain apdu length: 37 data: 903d00001f030000001800006162636465666768696a6b6c6d6e6f70717273747576777800
//   wrapped ciph  apdu length: 45 data: 903d0000270300000018000094761119877a8ab657663786402e14eb1425b3fd67ae6ebca428e10d91695bd000
            byte[] wrappedEncryptedApdu = cryp.preprocess(wrappedApdu, 7, DesfireFileCommunicationSettings.ENCIPHERED);
            writeToUiAppend(logTextView, printData("wrapped plain apdu", wrappedApdu));
            writeToUiAppend(logTextView, printData("wrapped ciph  apdu", wrappedEncryptedApdu));
            writeStandardFileResponse = isoDep.transceive(wrappedEncryptedApdu);
            //writeStandardFileResponse = isoDep.transceive(wrappedApdu);
            //writeToUiAppend(logTextView, printData("send APDU", wrappedApdu));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeStandardFileResponse", writeStandardFileResponse));
        System.arraycopy(returnStatusBytes(writeStandardFileResponse), 0, response, 0, 2);
        if (checkResponse(writeStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean writeToStandardFileAesMax70(TextView logTextView, byte fileNumber, byte[] data, byte[] response, Cryp cryp) {
        // some sanity checks to avoid any issues
        if (fileNumber < (byte) 0x00) return false;
        if (fileNumber > (byte) 0x0A) return false;
        if (data == null) return false;
        if (data.length == 0) return false;
        if (data.length > 70) return false; // DO NOT EXTEND THIS

        // write to file
        byte writeStandardFileCommand = (byte) 0x3d;
        int numberOfBytes = data.length;
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // no offset
        // todo use intToBytesLsb
        byte[] length = new byte[]{(byte) (numberOfBytes & 0xFF), (byte) 0xf00, (byte) 0x00}; // 32 bytes
        byte[] writeStandardFileParameters = new byte[(7 + data.length)]; // if encrypted we need to append the CRC
        writeStandardFileParameters[0] = fileNumber;
        System.arraycopy(offset, 0, writeStandardFileParameters, 1, 3);
        System.arraycopy(length, 0, writeStandardFileParameters, 4, 3);
        System.arraycopy(data, 0, writeStandardFileParameters, 7, data.length);

        writeToUiAppend(logTextView, printData("writeStandardFileParameters", writeStandardFileParameters));
        // writeStandardFileParameters length: 19 data: 07000000200000546865206c617a7920646f67
        byte[] writeStandardFileResponse = new byte[0];
        byte[] wrappedApdu;
        try {
            wrappedApdu = wrapMessage(writeStandardFileCommand, writeStandardFileParameters);

            // step 1 Desfire line 2001 write
            // fullApdu = preprocess(fullApdu, 7, cs);  // 7 = 1+3+3 (keyNo+off+len)
            // step 2 Desfire line 1439
            // private byte[] preprocess(byte[] apdu, int offset, DesfireFileCommunicationSettings commSett) {
            // line 1454: case ENCIPHERED: return preprocessEnciphered(apdu, offset);
            // step 3 Desfire line 1506
            // private byte[] preprocessEnciphered(byte[] apdu, int offset) {
            // step 4 Desfire line 1507
            // byte[] ciphertext = encryptApdu(apdu, offset, skey, iv, ktype);
            // step 5 Desfire line 1760
            // private static byte[] encryptApdu(byte[] apdu, int offset, byte[] sessionKey, byte[] iv, KeyType type) {
            // step 6 Desfire line 1776
            // crc = calculateApduCRC32C(apdu);
            // step 7 line 1737
            // private static byte[] calculateApduCRC32C(byte[] apdu) {
// btn
// ### write fullAPDU 1 length: 37 data: 903d00001f010000001800006162636465666768696a6b6c6d6e6f70717273747576777800
// ### write fullAPDU 2 length: 45 data: 903d0000270100000018000044c301ee90aef1a35377a91a053bbc51161fdc6f4c70d69b4ffed9ad760f701a00
// this method                                      | difference is filenumber
//   wrapped plain apdu length: 37 data: 903d00001f030000001800006162636465666768696a6b6c6d6e6f70717273747576777800
//   wrapped ciph  apdu length: 45 data: 903d0000270300000018000094761119877a8ab657663786402e14eb1425b3fd67ae6ebca428e10d91695bd000
            byte[] wrappedEncryptedApdu = cryp.preprocess(wrappedApdu, 7, DesfireFileCommunicationSettings.ENCIPHERED);
            writeToUiAppend(logTextView, printData("wrapped plain apdu", wrappedApdu));
            writeToUiAppend(logTextView, printData("wrapped ciph  apdu", wrappedEncryptedApdu));
            writeStandardFileResponse = isoDep.transceive(wrappedEncryptedApdu);
            //writeStandardFileResponse = isoDep.transceive(wrappedApdu);
            //writeToUiAppend(logTextView, printData("send APDU", wrappedApdu));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeStandardFileResponse", writeStandardFileResponse));
        System.arraycopy(returnStatusBytes(writeStandardFileResponse), 0, response, 0, 2);
        if (checkResponse(writeStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
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
    private byte[] preprocess(byte[] apdu, int offset, DesfireFileCommunicationSettings commSett) {
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
    private byte[] preprocessAes(byte[] apdu, int offset) {
        if (skey == null) {
            Log.e(TAG, "preprocess: skey is null");
            return apdu;
        }
        return preprocessEnciphered(apdu, offset);
    }


    // calculate CRC and append, encrypt, and update global IV
    private byte[] preprocessEnciphered(byte[] apdu, int offset) {
        writeToUiAppend(readResult, printData("# preprocessEnciphered apdu", apdu) + " offset " + offset);
        byte[] ciphertext = encryptApdu(apdu, offset, skey, iv, ktype);
        writeToUiAppend(readResult, printData("# preprocessEnciphered ciphertext", ciphertext));
        byte[] ret = new byte[5 + offset + ciphertext.length + 1];
        System.arraycopy(apdu, 0, ret, 0, 5 + offset);
        System.arraycopy(ciphertext, 0, ret, 5 + offset, ciphertext.length);
        ret[4] = (byte) (offset + ciphertext.length);

        if (ktype == KeyType.TKTDES || ktype == KeyType.AES) {
            iv = new byte[iv.length];
            System.arraycopy(ciphertext, ciphertext.length - iv.length, iv, 0, iv.length);
            writeToUiAppend(readResult, printData("# preprocessEnciphered new IV", iv));
        }

        return ret;
    }


    /* Only data is encrypted. Headers are left out (e.g. keyNo for credit). */
    private byte[] encryptApdu(byte[] apdu, int offset, byte[] sessionKey, byte[] iv, KeyType type) {
        writeToUiAppend(readResult, printData("# encryptApdu apdu", apdu) + " offset " + offset);
        writeToUiAppend(readResult, printData("# encryptApdu sessionKey", sessionKey) + " " + printData("iv", iv));
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
        writeToUiAppend(readResult, printData("# encryptApdu crc", crc));

        int padding = 0;  // padding=0 if block length is adequate
        if ((payloadLen - offset + crc.length) % blockSize != 0)
            padding = blockSize - (payloadLen - offset + crc.length) % blockSize;
        int ciphertextLen = payloadLen - offset + crc.length + padding;
        byte[] plaintext = new byte[ciphertextLen];
        System.arraycopy(apdu, 5 + offset, plaintext, 0, payloadLen - offset);
        System.arraycopy(crc, 0, plaintext, payloadLen - offset, crc.length);
        writeToUiAppend(readResult, printData("# encryptApdu plaintext", plaintext));
        return send(sessionKey, plaintext, type, iv);
    }

    // uses nfcjLib/util/CRC32.java
    // CRC32 calculated over INS+header+data
    private static byte[] calculateApduCRC32C(byte[] apdu) {
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

    // uses nfcjLib/util/CRC32.java
    private static byte[] calculateApduCRC32R(byte[] apdu, int length) {
        byte[] data = new byte[length + 1];
        System.arraycopy(apdu, 0, data, 0, length);// response code is at the end
        return CRC32.get(data);
    }

    /**
     * codes taken from DESFireEV1.java END
     */

    private byte[] getFileSettingsRecord(TextView logTextView, byte fileNumber, byte[] response) {
        byte getFileSettingsCommand = (byte) 0xf5;
        byte[] getFileSettingsParameters = new byte[1];
        getFileSettingsParameters[0] = fileNumber;
        byte[] getFileSettingsResponse;
        try {
            getFileSettingsResponse = isoDep.transceive(wrapMessage(getFileSettingsCommand, getFileSettingsParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("getFileSettingsResponse", getFileSettingsResponse));
        System.arraycopy(returnStatusBytes(getFileSettingsResponse), 0, response, 0, 2);
        if (checkResponse(getFileSettingsResponse)) {
            return getFileSettingsResponse;
        } else {
            return null;
        }
    }

    // THIS IS NOT WORKING BECAUSE OF MISSING ENCRYPTION !!!
    private boolean changeApplicationKeyDes(TextView logTextView, byte keyNumber, byte[] newKey, byte[] oldKey, byte[] response) {
        // some checks to avoid any bricked tags...
        if (newKey == null) return false;
        if (oldKey == null) return false;
        if (newKey.length != 8) return false; // des key length is 8
        if (oldKey.length != 8) return false; // des key length is 8
        if ((keyNumber < 0) | (keyNumber > 0x0d)) return false; // 14 keys are allowed, 0..13 dec

        byte changeKeyCommand = (byte) 0xc4;

        // this is the apdu from DESFireEv1 changeKey for a DES key
        // apdu: 90 C4 00 00 19 02 1D D7 C0 06 70 20 16 80 B0 93 C0 B5 0D 94 D0 65 42 75 D4 E6 38 99 5C 96 00
        //                   19 = 25 bytes data
        //                      02 ..                                                 24 bytes       5c
        //                                                                                              96 crc ?

        byte[] changeKeyParameters = new byte[17];
        changeKeyParameters[0] = keyNumber;
        System.arraycopy(newKey, 0, changeKeyParameters, 1, 3);
        System.arraycopy(oldKey, 0, changeKeyParameters, 4, 3);
        writeToUiAppend(logTextView, printData("changeKeyParameters", changeKeyParameters));
        byte[] changeKeyResponse = new byte[0];
        try {
            changeKeyResponse = isoDep.transceive(wrapMessage(changeKeyCommand, changeKeyParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
        }
        writeToUiAppend(logTextView, printData("changeKeyResponse", changeKeyResponse));
        System.arraycopy(returnStatusBytes(changeKeyResponse), 0, response, 0, 2);
        if (checkResponse(changeKeyResponse)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'9100' at the end means success
     * and the method returns the data without 0x'9100' at the end
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponse(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x9100) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'91AF' at the end means success
     * but there are more data frames available
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponseMoreData(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91AF) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'91BE' at the end means failure
     * because of an Boundary Error
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponseBoundaryError(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91BE) {
            return true;
        } else {
            return false;
        }
    }

    private byte[] returnStatusBytes(byte[] data) {
        return Arrays.copyOfRange(data, (data.length - 2), data.length);
    }

    /**
     * checks if the response has an 0x'91de' at the end means the data
     * element is already existing
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return true is code is 91DE
     */
    private boolean checkDuplicateError(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status != 0x91DE) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Set the version on a DES key. Each least significant bit of each byte of
     * the DES key, takes one bit of the version. Since the version is only
     * one byte, the information is repeated if dealing with 16/24-byte keys.
     *
     * @param a       1K/2K/3K 3DES
     * @param offset  start position of the key within a
     * @param length  key length
     * @param version the 1-byte version
     */
    // source: nfcjLib
    private static void setKeyVersion(byte[] a, int offset, int length, byte version) {
        if (length == 8 || length == 16 || length == 24) {
            for (int i = offset + length - 1, j = 0; i >= offset; i--, j = (j + 1) % 8) {
                a[i] &= 0xFE;
                a[i] |= ((version >>> j) & 0x01);
            }
        }
    }


    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        System.out.println("NFC tag discovered");

        //nfcA = null;
        isoDep = null;
        tagSaved = tag;
        try {
            isoDep = IsoDep.get(tag);
            //nfcA = NfcA.get(tag);
            //if (nfcA != null) {
            if (isoDep != null) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is IsoDep compatible",
                            Toast.LENGTH_SHORT).show();
                });

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                runOnUiThread(() -> {
                    readResult.setText("");
                    readResult.setBackgroundColor(getResources().getColor(R.color.white));
                });

                // enhanced function
                //DefaultIsoDepWrapper isoDepWrapper = new DefaultIsoDepWrapper(isoDep);
                //defaultIsoDepAdapter = new DefaultIsoDepAdapter(isoDepWrapper, false);
                IsoDepWrapper isoDepWrapper1 = new DefaultIsoDepWrapper(isoDep);
                desFireAdapter = new DESFireAdapter(isoDepWrapper1, true);

                //nfcA.connect();
                isoDep.connect();

                // enhanced functions
                nfcjTag = mifare_desfire_tag_new();
                nfcjTag.setActive(1);
                //nfcjTag.setIo(defaultIsoDepAdapter);
                //nfcjTag.setIo(isoDepWrapper1);
                desfireTag = new DesfireTag();


                System.out.println("*** tagId: " + Utils.bytesToHex(tag.getId()));

                // tag ID
                tagIdByte = tag.getId();
                runOnUiThread(() -> {
                    tagId.setText(Utils.bytesToHex(tagIdByte));
                });

                byte[] response = new byte[0];

                writeToUiAppend(readResult, "Trying to read without authentication");

                // https://github.com/codebutler/farebot/blob/master/farebot-card-desfire/src/main/java/com/codebutler/farebot/card/desfire/DesfireProtocol.java

                // get card uid
                String getCardUidCommand = "9051000000";
                //byte[] getCardUidResponse = nfcA.transceive(Utils.hexStringToByteArray(getCardUidCommand));
                byte[] getCardUidResponse = isoDep.transceive(Utils.hexStringToByteArray(getCardUidCommand));
                writeToUiAppend(readResult, "getCardUidResponse: " + Utils.bytesToHex(getCardUidResponse));
                // this should fail with 91 ae

                // do DES auth
                String getChallengeCommand = "901a0000010000";
                //String getChallengeCommand = "9084000000"; // IsoGetChallenge

                //byte[] getChallengeResponse = nfcA.transceive(Utils.hexStringToByteArray(getChallengeCommand));
                //byte[] getChallengeResponse = nfcA.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) 0x01} ));
                byte[] getChallengeResponse = isoDep.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) 0x00}));
                writeToUiAppend(readResult, "getChallengeResponse: " + Utils.bytesToHex(getChallengeResponse));
                // cf5e0ee09862d90391af
                // 91 af at the end shows there is more data

                byte[] challenge = Arrays.copyOf(getChallengeResponse, getChallengeResponse.length - 2);
                writeToUiAppend(readResult, "challengeResponse: " + Utils.bytesToHex(challenge));

                // Of course the rndA shall be a random number,
                // but we will use a constant number to make the example easier.
                byte[] rndA = Utils.hexStringToByteArray("0001020304050607");
                writeToUiAppend(readResult, printData("rndA", rndA));

                // This is the default key for a blank DESFire card.
                // defaultKey = 8 byte array = [0x00, ..., 0x00]
                byte[] defaultDESKey = Utils.hexStringToByteArray("0000000000000000");
                byte[] IV = new byte[8];

                // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
                byte[] rndB = decrypt(challenge, defaultDESKey, IV);
                writeToUiAppend(readResult, printData("rndB", rndB));
                // Rotate left the rndB byte[] leftRotatedRndB = rotateLeft(rndB);
                byte[] leftRotatedRndB = rotateLeft(rndB);
                writeToUiAppend(readResult, printData("leftRotatedRndB", leftRotatedRndB));
                // Concatenate the RndA and rotated RndB byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
                byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
                writeToUiAppend(readResult, printData("rndA_rndB", rndA_rndB));

                // Encrypt the bytes of the last step to get the challenge answer byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
                IV = challenge;
                byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
                writeToUiAppend(readResult, printData("challengeAnswer", challengeAnswer));

                IV = Arrays.copyOfRange(challengeAnswer, 8, 16);
                /*
                    Build and send APDU with the answer. Basically wrap the challenge answer in the APDU.
                    The total size of apdu (for this scenario) is 22 bytes:
                    > 0x90 0xAF 0x00 0x00 0x10 [16 bytes challenge answer] 0x00
                */
                byte[] challengeAnswerAPDU = new byte[22];
                challengeAnswerAPDU[0] = (byte) 0x90; // CLS
                challengeAnswerAPDU[1] = (byte) 0xAF; // INS
                challengeAnswerAPDU[2] = (byte) 0x00; // p1
                challengeAnswerAPDU[3] = (byte) 0x00; // p2
                challengeAnswerAPDU[4] = (byte) 0x10; // data length: 16 bytes
                challengeAnswerAPDU[challengeAnswerAPDU.length - 1] = (byte) 0x00;
                System.arraycopy(challengeAnswer, 0, challengeAnswerAPDU, 5, challengeAnswer.length);
                writeToUiAppend(readResult, printData("challengeAnswerAPDU", challengeAnswerAPDU));

                /*
                 * Sending the APDU containing the challenge answer.
                 * It is expected to be return 10 bytes [rndA from the Card] + 9100
                 */
                byte[] challengeAnswerResponse = isoDep.transceive(challengeAnswerAPDU);
                // response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
                writeToUiAppend(readResult, printData("challengeAnswerResponse", challengeAnswerResponse));
                byte[] challengeAnswerResp = Arrays.copyOf(challengeAnswerResponse, getChallengeResponse.length - 2);
                writeToUiAppend(readResult, printData("challengeAnswerResp", challengeAnswerResp));

                /*
                 * At this point, the challenge was processed by the card. The card decrypted the
                 * rndA rotated it and sent it back.
                 * Now we need to check if the RndA sent by the Card is valid.
                 */// encrypted rndA from Card, returned in the last step byte[] encryptedRndAFromCard = response.getData();

                // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
                //byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
                byte[] rotatedRndAFromCard = decrypt(challengeAnswerResp, defaultDESKey, IV);
                writeToUiAppend(readResult, printData("rotatedRndAFromCard", rotatedRndAFromCard));

                // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
                byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
                writeToUiAppend(readResult, printData("rndAFromCard", rndAFromCard));
                writeToUiAppend(readResult, "********** AUTH RESULT **********");
                if (Arrays.equals(rndA, rndAFromCard)) {
                    writeToUiAppend(readResult, "Authenticated");
                } else {
                    writeToUiAppend(readResult, "Authentication failes");
                    //System.err.println(" ### Authentication failed. ### ");
                    //log("rndA:" + toHexString(rndA) + ", rndA from Card: " + toHexString(rndAFromCard));
                }
                writeToUiAppend(readResult, "********** AUTH RESULT END **********");

                // now lets try to run the command from the beginning again
                getCardUidResponse = isoDep.transceive(Utils.hexStringToByteArray(getCardUidCommand));
                writeToUiAppend(readResult, printData("getCardUidResponse", getCardUidResponse));

                // https://github.com/skjolber/external-nfc-api/

                byte[] getVersionResponse;

                VersionInfo versionInfo = getVersionInfo();
                if (versionInfo != null) {
                    writeToUiAppend(readResult, versionInfo.dump());
                }


/*
                String getChallengeCommand2 = "90af000000";
                // byte[] getChallengeResponse2 = isoDep.transceive(Utils.hexStringToByteArray(getChallengeCommand2));
                byte[] getChallengeResponse2 = isoDep.transceive(wrapMessage((byte) 0xaf, null) );
                writeToUiAppend(readResult, "getChallengeResponse2: " + Utils.bytesToHex(getChallengeResponse2));

 */
            }

        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

/*
        writeToUiAppend(readResult, "SignatureVerified: " + signatureVerfied);
        runOnUiThread(() -> {
            if (signatureVerfied) {
                readResult.setBackgroundColor(getResources().getColor(R.color.light_background_green));
            } else {
                readResult.setBackgroundColor(getResources().getColor(R.color.light_background_red));
            }
        });

 */
    }

    // https://github.com/codebutler/farebot/blob/master/farebot-card-desfire/src/main/java/com/codebutler/farebot/card/desfire/DesfireProtocol.java

    private int byteArrayLength3InversedToInt(byte[] data) {
        return (data[2] & 0xff) << 16 | (data[1] & 0xff) << 8 | (data[0] & 0xff);
    }

    private int byteArrayLength3NonInversedToInt(byte[] data) {
        return (data[0] & 0xff) << 16 | (data[1] & 0xff) << 8 | (data[2] & 0xff);
    }

    public static int byteArrayLength4NonInversedToInt(byte[] bytes) {
        return bytes[0] << 24 | (bytes[1] & 0xFF) << 16 | (bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF);
    }

    //
    public static int byteArrayLength4InversedToInt(byte[] bytes) {
        return bytes[3] << 24 | (bytes[2] & 0xFF) << 16 | (bytes[1] & 0xFF) << 8 | (bytes[0] & 0xFF);
    }

    /**
     * Convert int to byte array (LSB).
     *
     * @param value the value to convert
     * @return 4-byte byte array
     */
    // BitOp.java / nfcjLib
    public static byte[] intToLsb(int value) {
        byte[] a = new byte[4];
        for (int i = 0; i < 4; i++) {
            a[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        return a;
    }

    /**
     * splits a byte array in chunks
     *
     * @param source
     * @param chunksize
     * @return a List<byte[]> with sets of chunksize
     */
    private static List<byte[]> divideArray(byte[] source, int chunksize) {
        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    public VersionInfo getVersionInfo() throws Exception {
        byte[] bytes = sendRequest(GET_VERSION_INFO);
        return new VersionInfo(bytes);
    }

    // Reference: http://neteril.org/files/M075031_desfire.pdf
    // Commands
    public static final byte GET_VERSION_INFO = (byte) 0x60;
    private static final byte GET_MANUFACTURING_DATA = (byte) 0x60;
    private static final byte GET_APPLICATION_DIRECTORY = (byte) 0x6A;
    private static final byte GET_ADDITIONAL_FRAME = (byte) 0xAF;
    private static final byte SELECT_APPLICATION = (byte) 0x5A;
    private static final byte READ_DATA = (byte) 0xBD;
    private static final byte READ_RECORD = (byte) 0xBB;
    private static final byte GET_VALUE = (byte) 0x6C;
    private static final byte GET_FILES = (byte) 0x6F;
    private static final byte GET_FILE_SETTINGS = (byte) 0xF5;

    // Status codes (Section 3.4)
    private static final byte OPERATION_OK = (byte) 0x00;
    private static final byte PERMISSION_DENIED = (byte) 0x9D;
    private static final byte AUTHENTICATION_ERROR = (byte) 0xAE;
    private static final byte ADDITIONAL_FRAME = (byte) 0xAF;

    void selectApp(int appId) throws Exception {
        byte[] appIdBuff = new byte[3];
        appIdBuff[0] = (byte) ((appId & 0xFF0000) >> 16);
        appIdBuff[1] = (byte) ((appId & 0xFF00) >> 8);
        appIdBuff[2] = (byte) (appId & 0xFF);

        sendRequest(SELECT_APPLICATION, appIdBuff);
    }

    int[] getFileList() throws Exception {
        byte[] buf = sendRequest(GET_FILES);
        int[] fileIds = new int[buf.length];
        for (int x = 0; x < buf.length; x++) {
            fileIds[x] = (int) buf[x];
        }
        return fileIds;
    }


    byte[] readFile(int fileNo) throws Exception {
        return sendRequest(READ_DATA, new byte[]{
                (byte) fileNo,
                (byte) 0x0, (byte) 0x0, (byte) 0x0,
                (byte) 0x0, (byte) 0x0, (byte) 0x0
        });
    }

    byte[] readRecord(int fileNum) throws Exception {
        return sendRequest(READ_RECORD, new byte[]{
                (byte) fileNum,
                (byte) 0x0, (byte) 0x0, (byte) 0x0,
                (byte) 0x0, (byte) 0x0, (byte) 0x0
        });
    }

    byte[] getValue(int fileNum) throws Exception {
        return sendRequest(GET_VALUE, new byte[]{
                (byte) fileNum
        });
    }

    private byte[] sendRequest(byte command) throws Exception {
        return sendRequest(command, null);
    }

    // todo take this as MASTER for sending commands to the card and receiving data
    private byte[] sendRequest(byte command, byte[] parameters) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        byte[] recvBuffer = isoDep.transceive(wrapMessage(command, parameters));
        writeToUiAppend(readResult, printData("sendRequest recvBuffer", recvBuffer));
        while (true) {
            if (recvBuffer[recvBuffer.length - 2] != (byte) 0x91) {
                throw new Exception("Invalid response");
            }

            output.write(recvBuffer, 0, recvBuffer.length - 2);

            byte status = recvBuffer[recvBuffer.length - 1];
            if (status == OPERATION_OK) {
                break;
            } else if (status == ADDITIONAL_FRAME) {
                recvBuffer = isoDep.transceive(wrapMessage(GET_ADDITIONAL_FRAME, null));
            } else if (status == PERMISSION_DENIED) {
                throw new AccessControlException("Permission denied");
            } else if (status == AUTHENTICATION_ERROR) {
                throw new AccessControlException("Authentication error");
            } else {
                throw new Exception("Unknown status code: " + Integer.toHexString(status & 0xFF));
            }
        }
        return output.toByteArray();
    }

    private byte[] wrapMessage(byte command, byte[] parameters) throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null) {
            stream.write((byte) parameters.length);
            stream.write(parameters);
        }
        stream.write((byte) 0x00);

        return stream.toByteArray();
    }

    /**
     * section for efficient writing of data to the card with a length of more than frame size
     * Usually we can send unencrypted data of about 45 bytes length in one frame
     * If using AES encryption it is about a maximum of 24 bytes to send in one frame
     * The following code is taken from DESFireAdapter.java
     */

    // some constants
    //public static final byte OPERATION_OK = (byte)0x00;
    //public static final byte ADDITIONAL_FRAME = (byte)0xAF;
    public static final byte STATUS_OK = (byte) 0x91;

    public static final int MAX_CAPDU_SIZE = 55;
    public static final int MAX_RAPDU_SIZE = 60;
    public boolean print = true;
    /**
     * Send compressed command message
	 *
     * @param adpu
	 * @return
     * @throws Exception
	 */

    // this is called DESFireEV1 byte[] responseAPDU = adapter.transmitChain(fullApdu);
    public byte[] transmitChain(byte[] adpu) throws Exception {
        return receiveResponseChain(sendRequestChain(adpu));
    }

    public byte[] receiveResponseChain(byte[] response) throws IOException, Exception {

        if(response[response.length - 2] == STATUS_OK && response[response.length - 1] == OPERATION_OK) {
            return response;
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        do {
            if (response[response.length - 2] != STATUS_OK) {
                throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }

            output.write(response, 0, response.length - 2);

            byte status = response[response.length - 1];
            if (status == OPERATION_OK) {
                return output.toByteArray();
            } else if (status != ADDITIONAL_FRAME) {
                throw new Exception("PICC error code while reading response: " + Integer.toHexString(status & 0xFF));
            }

            response = transmit(wrapMessage(ADDITIONAL_FRAME));
        } while(true);
    }

    public byte[] sendRequestChain(byte[] apdu) throws Exception {
        System.out.println("*** sendRequestChain apdu: " + Utils.bytesToHex(apdu));
        if(apdu.length <= MAX_CAPDU_SIZE) {
            return transmit(apdu);
        }
        int offset = 5; // data area of apdu

        byte nextCommand =  apdu[1];
        while(true) {
            int nextLength = Math.min(MAX_CAPDU_SIZE - 1, apdu.length - offset);

            byte[] request = wrapMessage(nextCommand, apdu, offset, nextLength);

            byte[] response = transmit(request);
            System.out.println("*** sendRequestChain response: " + Utils.bytesToHex(response));
            if (response[response.length - 2] != STATUS_OK) {
                throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }

            offset += nextLength;
            if(offset == apdu.length) {
                return response;
            }

            if(response.length != 2) {
                throw new IllegalArgumentException("Expected empty response payload while transmitting request");
            }
            byte status = response[response.length - 1];
            if (status != ADDITIONAL_FRAME) {
                throw new Exception("PICC error code: " + Integer.toHexString(status & 0xFF));
            }
            nextCommand = ADDITIONAL_FRAME;
        }

    }

    public static byte[] wrapMessage (byte command) throws Exception {
        return new byte[]{(byte) 0x90, command, 0x00, 0x00, 0x00};
    }

    public static byte[] wrapMessage (byte command, byte[] parameters, int offset, int length) throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null && length > 0) {
            // actually no length if empty length
            stream.write(length);
            stream.write(parameters, offset, length);
        }
        stream.write((byte) 0x00);

        return stream.toByteArray();
    }

    /**
     * Send a command to the card and return the response.
     *
     * @param command	the command
     * @return			the PICC response
     * @throws IOException
     */
    public byte[] transmit(byte[] command) throws IOException {

        if(print) {
            //Log.d(TAG, "===> " + getHexString(command, true) + " (" + command.length + ")");
            Log.d(TAG, "===> " + getHexString(command, true) + " (" + command.length + ")");
        }

        byte[] response = isoDep.transceive(command);

        if(print) {
            Log.d(TAG, "<=== " + getHexString(response, true) + " (" + command.length + ")");
        }

        return response;
    }

    public static String getHexString(byte[] a, boolean space) {
        StringBuilder sb = new StringBuilder();
        for (byte b : a) {
            sb.append(String.format("%02x", b & 0xff));
            if(space) {
                sb.append(' ');
            }
        }
        return sb.toString().trim().toUpperCase();
    }

    /**
     * section for efficient writing of data to the card with a length of more than frame size END
     */

    /***
     * Given a byte array, convert it to a hexadecimal representation.
     *
     * @param data: Byte Array
     * @return String containing the hexadecimal representation
     */
    private static String toHexString(byte[] data) {
        StringBuilder hexString = new StringBuilder();
        for (byte item : data) {
            String hex = String.format("%02x", item);
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * section for DES encryption
     */

    private static byte[] decrypt(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static byte[] encrypt(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static Cipher getCipher(int mode, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        IvParameterSpec algorithmParamSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, algorithmParamSpec);
        return cipher;
    }

    /**
     * section for AES encryption
     */

    private static byte[] decryptAes(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipherAes(Cipher.DECRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static byte[] encryptAes(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipherAes(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static Cipher getCipherAes(int mode, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec algorithmParamSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, algorithmParamSpec);
        return cipher;
    }

    private static byte[] rotateLeft(byte[] data) {
        byte[] rotated = new byte[data.length];

        rotated[data.length - 1] = data[0];

        for (int i = 0; i < data.length - 1; i++) {
            rotated[i] = data[i + 1];
        }
        return rotated;
    }

    private static byte[] rotateRight(byte[] data) {
        byte[] unrotated = new byte[data.length];

        for (int i = 1; i < data.length; i++) {
            unrotated[i] = data[i - 1];
        }

        unrotated[0] = data[data.length - 1];
        return unrotated;
    }

    private static byte[] concatenate(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];

        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }

        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }

        return concatenated;
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

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = message + "\n" + textView.getText().toString();
            textView.setText(newString);
            System.out.println(message);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }
}