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
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.IsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.file.DesfireFileCommunicationSettings;
import com.github.skjolber.desfire.ev1.model.file.RecordDesfireFile;
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

import de.androidcrypto.WriteCyclicFileBuilder;
import de.androidcrypto.WriteCyclicFileBuilderBuilder;
import nfcjlib.core.DESFireAdapter;
import nfcjlib.core.DESFireEV1;
import nfcjlib.core.KeyType;
import nfcjlib.core.util.AES;
import nfcjlib.core.util.CRC32;
import nfcjlib.core.util.TripleDES;


public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private final String TAG = "Main";

    Button btn2, btn3, btn4, btn5, btn6, btn7, btn8, btn9, btn10, btn11, btn12, btn13, btn14, btn15, btn16, btn17, btn18, btn19, btn20, btn21, btn22, btn23;
    Button btn24, btn25, btn26, btn27, btn28, btn29;
    EditText tagId, dataToWrite, readResult;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte;
    IsoDep isoDep;

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
        setContentView(R.layout.activity_main);

        tagId = findViewById(R.id.etVerifyTagId);
        dataToWrite = findViewById(R.id.etDataToWrite);
        readResult = findViewById(R.id.etVerifyResult);
        btn2 = findViewById(R.id.btn2);
        btn3 = findViewById(R.id.btn3);
        btn4 = findViewById(R.id.btn4);
        btn5 = findViewById(R.id.btn5);
        btn6 = findViewById(R.id.btn6);
        btn7 = findViewById(R.id.btn7);
        btn8 = findViewById(R.id.btn8);
        btn9 = findViewById(R.id.btn9);
        btn10 = findViewById(R.id.btn10);
        btn11 = findViewById(R.id.btn11);
        btn12 = findViewById(R.id.btn12);
        btn13 = findViewById(R.id.btn13);
        btn14 = findViewById(R.id.btn14);
        btn15 = findViewById(R.id.btn15);
        btn16 = findViewById(R.id.btn16);
        btn17 = findViewById(R.id.btn17);
        btn18 = findViewById(R.id.btn18);
        btn19 = findViewById(R.id.btn19);
        btn20 = findViewById(R.id.btn20);
        btn21 = findViewById(R.id.btn21);
        btn22 = findViewById(R.id.btn22);
        btn23 = findViewById(R.id.btn23);
        btn24 = findViewById(R.id.btn24);
        btn25 = findViewById(R.id.btn25);
        btn26 = findViewById(R.id.btn26);
        btn27 = findViewById(R.id.btn27);
        btn28 = findViewById(R.id.btn28);
        btn29 = findViewById(R.id.btn29);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        btn2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create application

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "create DesStandard application");
                // first select application 00 00 00
                byte[] responseData = new byte[2];
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                // get master key settings
                responseData = new byte[2];
                byte[] keySettings = getKeySettings(readResult, responseData);
                writeToUiAppend(readResult, printData("keySettings", keySettings));

                // create an application
                responseData = new byte[2];
                boolean createApplicationSuccess = createApplicationDes(readResult, AID_DesStandard, AID_DesStandard_number_of_keys, responseData);
                writeToUiAppend(readResult, "createApplication result: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createApplicationSuccess) {
                    writeToUiAppend(readResult, "the createApplication was not successful, aborted");
                    return;
                }
            }
        });

        btn3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // list applications

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "list applications on card");
                // first select application 00 00 00
                byte[] responseData = new byte[2];
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                // get application ids
                responseData = new byte[2];
                List<byte[]> applicationIdList = getApplicationIdsList(readResult, responseData);
                writeToUiAppend(readResult, "getApplicationIdsList response: " + Utils.bytesToHex(responseData));
                if (applicationIdList != null) {
                    for (int i = 0; i < applicationIdList.size(); i++) {
                        writeToUiAppend(readResult, "entry " + i + " app id : " + Utils.bytesToHex(applicationIdList.get(i)));
                    }
                } else {
                    writeToUiAppend(readResult, "getApplicationIdsList returned NULL");
                }

            }
        });

        btn4.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // select application and create a standard file

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "create a Standard File");

                // select the application
                byte[] responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_DesStandard, responseData);
                writeToUiAppend(readResult, "selectApplication success: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateSuccess = authenticateApplicationDes(readResult, AID_DesStandard_Key0_Number, AID_DesStandard_Key0, false, responseData);
                writeToUiAppend(readResult, "authenticateApplication result: " + authenticateSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateSuccess) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }

                // create the standard file
                responseData = new byte[2];
                boolean createStandardFileSuccess = createStandardFile(readResult, DesStandardFileFileNumber1, responseData);
                writeToUiAppend(readResult, "createStandardFile result: " + createStandardFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createStandardFileSuccess) {
                    writeToUiAppend(readResult, "the createStandardFile was not successful, aborted");
                    return;
                }
            }
        });

        btn5.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the free memory on the card
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "get free memory on card");

                // first select application 00 00 00
                byte[] responseData = new byte[2];
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                int freeMemoryOnCard = getFreeMemory(readResult, responseData);
                writeToUiAppend(readResult, "freeMemoryOnCard: " + freeMemoryOnCard + " with response: " + Utils.bytesToHex(responseData));
                if (freeMemoryOnCard == 0) {
                    writeToUiAppend(readResult, "the getFreeMemory was not successful, aborted");
                    return;
                }
            }
        });

        btn6.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // read from standard file

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "read from a Standard File");

                // select the application
                byte[] responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_DesStandard, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 and read rights to key1, so we need to authenticate with key 1 first to proceed
                boolean authenticateSuccess = authenticateApplicationDes(readResult, AID_DesStandard_Key1_Number, AID_DesStandard_Key1, false, responseData);
                writeToUiAppend(readResult, "authenticateApplication result: " + authenticateSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateSuccess) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }

                // read from standard file
                responseData = new byte[2];
                byte[] readStandardFile = readFromStandardFile(readResult, DesStandardFileFileNumber1, responseData);
                writeToUiAppend(readResult, printData("readStandardFile", readStandardFile) + " with response: " + Utils.bytesToHex(responseData));
                if (!checkResponse(responseData)) {
                    writeToUiAppend(readResult, "the readStandardFile was not successful, aborted");
                } else {
                    writeToUiAppend(readResult, "readStandardFileResponse: " + new String(readStandardFile, StandardCharsets.UTF_8));
                }
            }
        });

        btn7.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // write to standard file

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "write to Standard file");


                String data = dataToWrite.getText().toString();
                if (TextUtils.isEmpty(data)) {
                    Toast.makeText(getApplicationContext(),
                            "please enter some data to write on tag",
                            Toast.LENGTH_SHORT).show();
                    return;
                }

                // select the application
                byte[] responseData = new byte[2];
                boolean success = selectApplicationDes(readResult, AID_DesStandard, responseData);
                writeToUiAppend(readResult, "selectApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 and read rights to key1, so we need to authenticate with key 2 (write rights) first to proceed
                boolean authenticateSuccess = authenticateApplicationDes(readResult, AID_DesStandard_Key2_Number, AID_DesStandard_Key2, false, responseData);
                writeToUiAppend(readResult, "authenticateApplication result: " + success + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateSuccess) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }

                // write to standard file
                responseData = new byte[2];
                boolean writeStandardFileSuccess = writeToStandardFile(readResult, DesStandardFileFileNumber1, data.getBytes(StandardCharsets.UTF_8), responseData);
                writeToUiAppend(readResult, "writeStandardFile result: " + writeStandardFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeStandardFileSuccess) {
                    writeToUiAppend(readResult, "the writeStandardFile was not successful, aborted");
                    return;
                }
            }
        });

        btn8.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create value file

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "create a Value File");

                // first... create the application from MasterFile activation
                byte[] responseData = new byte[2];

                // select the masterfile application
                responseData = new byte[2];
                boolean selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectMasterApplication result: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, AID_Master_Key0_Number, AID_Master_Key0, false, responseData);
                writeToUiAppend(readResult, "authenticateMasterApplication result: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the authenticationMaster was not successful, aborted");
                    return;
                }

                // create the new application
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean createApplicationSuccess = createApplicationDes(readResult, AID_DesValue, AID_DesValue_number_of_keys, responseData);
                writeToUiAppend(readResult, "createApplication result: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the createApplication was not successful, aborted");
                    return;
                }

                // select the application
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_DesValue, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

/*
                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateSuccess = authenticateApplicationDes(readResult, AID_DesValue_Key0_Number, AID_DesValue_Key0, responseData);
                writeToUiAppend(readResult, "authenticateApplication result: " + authenticateSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateSuccess) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }
*/
                // create the value file
                responseData = new byte[2];
                boolean createValueFileSuccess = createValueFile(readResult, DesValueFileFileNumber1, responseData);
                writeToUiAppend(readResult, "createValueFile result: " + createValueFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createValueFileSuccess) {
                    writeToUiAppend(readResult, "the createValueFile was not successful, aborted");
                    return;
                }
            }
        });

        btn9.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // increase value file

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "increase a Value File");

                // select application
                // select the application
                byte[] responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_DesValue, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                // as we set key 1 as read right we need to authenticate with key 1
                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 1 first to proceed reading
                boolean authenticateReadSuccess = authenticateApplicationDes(readResult, AID_DesValue_Key1_Number, AID_DesValue_Key1, false, responseData);
                writeToUiAppend(readResult, "authenticateRead result: " + authenticateReadSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateReadSuccess) {
                    writeToUiAppend(readResult, "the authenticationRead was not successful, aborted");
                    return;
                }

                // read the existing value
                int actualValue = readFromValueFile(readResult, DesValueFileFileNumber1, responseData);
                // check response if read was success
                //writeToUiAppend(readResult, printData("responseData", responseData));
                if (checkResponse(responseData)) {
                    writeToUiAppend(readResult, "The value read from value file is: " + actualValue);
                } else {
                    writeToUiAppend(readResult, "there was an error during reading the value, aborted");
                    return;
                }

                // The Credit command requires a preceding authentication with the key specified for 'Read&Write' access
                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed writing
                boolean authenticateWriteSuccess = authenticateApplicationDes(readResult, AID_DesValue_Key0_Number, AID_DesValue_Key0, false, responseData);
                writeToUiAppend(readResult, "authenticateWrite result: " + authenticateWriteSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateWriteSuccess) {
                    writeToUiAppend(readResult, "the authenticationWrite was not successful, aborted");
                    return;
                }

                // increase = credit value file
                responseData = new byte[2];
                int increaseValue = 7;
                boolean increaseSuccess = increaseValueFile(readResult, DesValueFileFileNumber1, increaseValue, responseData);
                writeToUiAppend(readResult, "increase result: " + increaseSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!increaseSuccess) {
                    writeToUiAppend(readResult, "the increase was not successful, aborted");
                    // check for boundery error
                    if (checkResponseBoundaryError(responseData)) {
                        writeToUiAppend(readResult, "Boundary error: the increased value is higher then the upper limit");
                    }
                    return;
                } else {
                    writeToUiAppend(readResult, "The value file was increased by " + increaseValue + ". Run commit !");
                }

                // don't forget to submit
                responseData = new byte[2];
                boolean commitSuccess = commitWriteToFile(readResult, responseData);
                writeToUiAppend(readResult, "commit result: " + commitSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!commitSuccess) {
                    writeToUiAppend(readResult, "the commit was not successful, aborted");
                    return;
                } else {
                    writeToUiAppend(readResult, "The value file was increased by " + increaseValue);
                }

                // as we set key 1 as read right we need to authenticate with key 1
                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 1 first to proceed reading
                boolean authenticateRead2Success = authenticateApplicationDes(readResult, AID_DesValue_Key1_Number, AID_DesValue_Key1, false, responseData);
                writeToUiAppend(readResult, "authenticateRead2 result: " + authenticateRead2Success + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateRead2Success) {
                    writeToUiAppend(readResult, "the authenticationRead2 was not successful, aborted");
                    return;
                }

                // read the increased value
                int actualValue2 = readFromValueFile(readResult, DesValueFileFileNumber1, responseData);
                // check response if read was success
                //writeToUiAppend(readResult, printData("responseData", responseData));
                if (checkResponse(responseData)) {
                    writeToUiAppend(readResult, "The value read from value file is: " + actualValue2);
                } else {
                    writeToUiAppend(readResult, "there was an error during reading the value 2, aborted");
                    return;
                }

                // to decrease a value we do not need the R&W access:
                // The Debit command requires a preceding authentication with one of the keys specified for Read, Write or Read&Write access

                // I'm using key 2 now just for testing the write key
                // as we set key 2 as write right we need to authenticate with key 2
                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 1 first to proceed reading
                boolean authenticateWrite2Success = authenticateApplicationDes(readResult, AID_DesValue_Key2_Number, AID_DesValue_Key2, false, responseData);
                writeToUiAppend(readResult, "authenticateWrite2 result: " + authenticateWrite2Success + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateWrite2Success) {
                    writeToUiAppend(readResult, "the authenticationWrite2 was not successful, aborted");
                    return;
                }

                // now decrease the value
                responseData = new byte[2];
                int decreaseValue = 17;
                boolean decreaseSuccess = decreaseValueFile(readResult, DesValueFileFileNumber1, decreaseValue, responseData);
                writeToUiAppend(readResult, "decrease result: " + decreaseSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!decreaseSuccess) {
                    writeToUiAppend(readResult, "the decrease was not successful, aborted");
                    if (checkResponseBoundaryError(responseData)) {
                        writeToUiAppend(readResult, "Boundary error: the decreased value is lower then the lower limit");
                    }
                    return;
                } else {
                    writeToUiAppend(readResult, "The value file was decreased by " + decreaseValue + ". Run commit !");
                }

                // don't forget to submit
                responseData = new byte[2];
                commitSuccess = commitWriteToFile(readResult, responseData);
                writeToUiAppend(readResult, "commit result: " + commitSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!commitSuccess) {
                    writeToUiAppend(readResult, "the commit was not successful, aborted");
                    return;
                } else {
                    writeToUiAppend(readResult, "The value file was decreased by " + decreaseValue);
                }

                // as we set key 1 as read right we need to authenticate with key 1
                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 1 first to proceed reading
                boolean authenticateRead3Success = authenticateApplicationDes(readResult, AID_DesValue_Key1_Number, AID_DesValue_Key1, false, responseData);
                writeToUiAppend(readResult, "authenticateRead3 result: " + authenticateRead3Success + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateRead3Success) {
                    writeToUiAppend(readResult, "the authenticationRead3 was not successful, aborted");
                    return;
                }

                // read the decreased value
                int actualValue3 = readFromValueFile(readResult, DesValueFileFileNumber1, responseData);
                // check response if read was success
                //writeToUiAppend(readResult, printData("responseData", responseData));
                if (checkResponse(responseData)) {
                    writeToUiAppend(readResult, "The value read from value file is: " + actualValue3);
                } else {
                    writeToUiAppend(readResult, "there was an error during reading the value 3, aborted");
                    return;
                }
            }
        });

        btn10.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // delete an application

                /*
                // first select application 00 00 00
                byte selectApplicationCommand = (byte) 0x5a;
                byte[] masterfileApplication = new byte[3]; // 00 00 00
                byte[] selectMasterfileApplicationResponse = new byte[0];
                try {
                    selectMasterfileApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, masterfileApplication));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("selectMasterfileApplicationResponse", selectMasterfileApplicationResponse));

                */
/*
                // get application ids
                byte getApplicationIdsCommand = (byte) 0x6a;
                byte[] getApplicationIdsResponse = new byte[0];
                try {
                    getApplicationIdsResponse = isoDep.transceive(wrapMessage(getApplicationIdsCommand, null));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("getApplicationIdsResponse", getApplicationIdsResponse));

                byte[] applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
                List<byte[]> applicationIdList = divideArray(applicationListBytes, 3);
                for (int i = 0; i < applicationIdList.size(); i++) {
                    writeToUiAppend(readResult, "app id 1: " + Utils.bytesToHex(applicationIdList.get(i)));
                }
*/
                // depending on the PICC Master Key Settings we need to authenticate with the MasterFile auth key
                // or with the Application masterKey
                // in my example the setting is "no MasterFile key needed for application creation/deletion"
                // let's authenticate now the application file

                // now select the application to delete
                byte selectApplicationCommand = (byte) 0x5a;
                byte[] applicationIdentifier = new byte[]{0x05, 0x06, 0x07};
                byte[] selectApplicationResponse = new byte[0];
                try {
                    selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("selectApplicationResponse", selectApplicationResponse));

                /**
                 * start of the authentication
                 */

                // the application 05 06 07 was created using TKDES
                DESFireEV1 desfire = new DESFireEV1();
                try {
                    // set adapter
                    //desfire.setAdapter(defaultIsoDepAdapter);
                    //desfire.setAdapter(defaultIsoDepAdapter);
                    desfire.setAdapter(desFireAdapter);
                    // public boolean authenticate(byte[] key, byte keyNo, DesfireKeyType type) throws IOException {
                    boolean suc = desfire.authenticate(new byte[24], (byte) 0, KeyType.TKTDES);
                    writeToUiAppend(readResult, "suc in auth for " + suc);

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "IOException: " + e.getMessage());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                /**
                 * end of the authentication
                 */

                // delete an application
                byte getDeleteApplicationCommand = (byte) 0xda;
                byte[] APPLICATION_ID = new byte[]{0x05, 0x06, 0x07};
                writeToUiAppend(readResult, "start of deletion process for AID " + Utils.bytesToHex(APPLICATION_ID));
                byte[] getDeleteApplicationResponse = new byte[0];
                try {
                    getDeleteApplicationResponse = isoDep.transceive(wrapMessage(getDeleteApplicationCommand, APPLICATION_ID));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("getDeleteApplicationResponse", getDeleteApplicationResponse));
                // 91 00
            }
        });

        btn11.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // format the tag
                // warning the tag will be deleted without any further note
                // now select the application to delete
                byte formatPiccCommand = (byte) 0xfc;
                byte[] formatPiccResponse = new byte[0];
                try {
                    formatPiccResponse = isoDep.transceive(wrapMessage(formatPiccCommand, null));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("formatPiccResponse", formatPiccResponse));
                writeToUiAppend(readResult, "*** format card ***");
                if (checkResponse(formatPiccResponse)) {
                    writeToUiAppend(readResult, "The formatPicc was successful");
                } else {
                    writeToUiAppend(readResult, "The formatPicc has FAILED");
                }
            }
        });

        btn12.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will create an application that contains a log file in CyclicRecordFile
                // in the end it writes one log entry

                // create an application
                byte numberOfKeys = (byte) 0x03;
                byte[] responseData = new byte[2];
                boolean success = createApplicationDes(readResult, AID_DesLog, numberOfKeys, responseData);
                writeToUiAppend(readResult, "createApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));
                if (checkDuplicateError(responseData)) {
                    writeToUiAppend(readResult, "the application was not created as it already exists, proceed");
                }

                // select the application
                success = selectApplicationDes(readResult, AID_DesLog, responseData);
                writeToUiAppend(readResult, "selectApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));

                // todo any checks on response ?

                // create the CyclicRecordFile
                byte createCyclicFileCommand = (byte) 0xc0;

                //byte fileNumber = (byte) 0x08;
                byte fileNumber = DesLogCyclicFileFileNumber;
                //fileNumber = (byte) 0x09; // test with auth key 00
                //byte numberOfRecords = (byte) 0x06; // 5 records (+1 record as spare record for writing data before committing), fixed for this method
                byte sizeOfRecord = (byte) 0x20; // 0x20 = 32 bytes, fixed for this method
                byte commSettingsByte = 0; // todo check, this should be plain communication without any encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
                byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
                // here we are using key 1 for every access !
                byte accessRightsRwCar = (byte) 0x11; // Read&Write Access & ChangeAccessRights
                byte accessRightsRW = (byte) 0x11; // Read Access & Write Access
                /*
                There are four different Access Rights (2 bytes for each file) stored for each file within
                each application:
                - Read Access
                - Write Access
                - Read&Write Access
                - ChangeAccessRights
                 */

                // create a value file in the new application: fileNo=6, cs=3
                //ar1 = 0x00;  // RW|CAR
                //ar2 = 0x00;  // R|W

                /* @param payload	10-byte array with the following contents:
                 * 					<br>file number (1 byte),
                 * 					<br>communication settings (1 byte),
                 * 					<br>access rights (2 bytes: RW||CAR||R||W),
                 * 					<br>size of a single record size (3 bytes LSB),
                 * 					<br>maximum amount of records (3 bytes LSB)
                 * @return			{@code true} on success, {@code false} otherwise
                 * @throws IOException
                 */

                byte[] createCyclicFileParameters = new byte[10]; // just to show the length
                createCyclicFileParameters = new byte[]{
                        fileNumber, commSettingsByte, accessRightsRwCar, accessRightsRW,
                        sizeOfRecord, 0, 0,   // size of record fixed to dec 32
                        DesLogCyclicFileNumberOfRecords, 0, 0 // maximum amount of records, fixed to dec 5
                };

                writeToUiAppend(readResult, printData("createCyclicFileParameters", createCyclicFileParameters));
                byte[] createCyclicFileResponse = new byte[0];
                try {
                    createCyclicFileResponse = isoDep.transceive(wrapMessage(createCyclicFileCommand, createCyclicFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("createCyclicFileResponse", createCyclicFileResponse));
                if (checkDuplicateError(createCyclicFileResponse)) {
                    writeToUiAppend(readResult, "the file was not created as it already exists, proceed");
                }

                // do the auth with DesfireEv1 (working
                /*
                DESFireEV1 desFireEV1 = new DESFireEV1();
                writeToUiAppend(readResult, "*** authenticate with DesfireEv1 ***");
                try {
                    // set adapter
                    desFireEV1.setAdapter(defaultIsoDepAdapter);
                    // public boolean authenticate(byte[] key, byte keyNo, DesfireKeyType type) throws IOException {
                    boolean suc = desFireEV1.authenticate(applicationIdentifier_DesLog_key1, (byte) 0x01, DESFireEV1.DesfireKeyType.DES);
                    writeToUiAppend(readResult, "suc in auth for " + suc);

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "IOException: " + e.getMessage());
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "Exception: " + e.getMessage());
                    return;
                }
                 */

                // authenticate own
                responseData = new byte[2]; // todo work on this
                // we set the read + write key to key 1 so we need to authenticate with key 1 first to proceed
                success = authenticateApplicationDes(readResult, (byte) 0x01, AID_DesLog_Key1, false, responseData);
                writeToUiAppend(readResult, "authenticateApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));
                if (!success) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }

                // write to the CyclicFile
                byte writeFileCommand = (byte) 0x3b;
                // byte fileNumberLogCyclicFile; // is defined as constant
                byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
                byte[] dataLength;
                String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
                int contentLengthInt = contentString.length();
                // todo be more universal with this. The created record size is 32 so this data is fitting into one record
                byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
                byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
                byte[] writeFileParameters = new byte[(contentLengthInt + 7)];
                writeFileParameters[0] = DesLogCyclicFileFileNumber;
                System.arraycopy(offset, 0, writeFileParameters, 1, 3);
                System.arraycopy(contentLength, 0, writeFileParameters, 4, 3);
                System.arraycopy(content, 0, writeFileParameters, 7, contentLengthInt);
                writeToUiAppend(readResult, printData("writeFileParameters", writeFileParameters));
                byte[] writeFileResponse = new byte[0];
                try {
                    writeFileResponse = isoDep.transceive(wrapMessage(writeFileCommand, writeFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("writeFileResponse", writeFileResponse));

                // don't forget to commit all changes
                byte commitCommand = (byte) 0xc7;
                byte[] commitResponse = new byte[0];
                try {
                    commitResponse = isoDep.transceive(wrapMessage(commitCommand, null));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("commitResponse", commitResponse));

            }
        });

        btn13.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // append 3 log entries and display data

                // select the application
                byte[] responseData = new byte[2];
                boolean success = selectApplicationDes(readResult, AID_DesLog, responseData);
                writeToUiAppend(readResult, "selectApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2]; // todo work on this
                // we set the read + write key to key 1 so we need to authenticate with key 1 first to proceed
                boolean authenticateSuccess = authenticateApplicationDes(readResult, (byte) 0x01, AID_DesLog_Key1, false, responseData);
                writeToUiAppend(readResult, "authenticateApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateSuccess) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }

                // write 3 times to cyclic file
                for (int i = 0; i < 3; i++) {
                    // write
                    responseData = new byte[2];
                    boolean writeToCyclicFileSuccess = writeToCyclicFile(readResult, DesLogCyclicFileFileNumber, responseData);
                    writeToUiAppend(readResult, "writeToCyclicFile success: " + success + " with response: " + Utils.bytesToHex(responseData));
                    if (!writeToCyclicFileSuccess) {
                        writeToUiAppend(readResult, "writeToCyclicFile was not successful, aborted");
                        return;
                    }
                    // commit
                    responseData = new byte[2];
                    boolean writeToFileCommitSuccess = commitWriteToFile(readResult, responseData);
                    writeToUiAppend(readResult, "writeToFileCommit success: " + success + " with response: " + Utils.bytesToHex(responseData));
                    if (!writeToFileCommitSuccess) {
                        writeToUiAppend(readResult, "writeToFileCommit was not successful, aborted");
                        return;
                    }
                }

                // read cyclic file data
                // define some data
                byte[] recordNumber = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // record 0 is the youngest record
                byte[] numberOfRecords = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x00}; // read just one record
                //numberOfRecords[0] = numberOfRecordsLogCyclicFile;
                //numberOfRecords[0] = (byte) 0x05;
                for (int i = 0; i < 5; i++) {
                    recordNumber[0] = (byte) (i & 0xFF);
                    byte[] readFileData = readFromCyclicFile(readResult, DesLogCyclicFileFileNumber, recordNumber, numberOfRecords, responseData, true);
                    writeToUiAppend(readResult, printData("readFileData", readFileData));
                    writeToUiAppend(readResult, "record " + i + " : " + new String(readFileData, StandardCharsets.UTF_8));
                    byte[] readFileStatus = returnStatusBytes(readFileData);
                    boolean readData = false;
                    if (readFileStatus[1] == (byte) 0xAF) readData = true;
                    while (readData == true) {
                        readFileData = readFromCyclicFile(readResult, DesLogCyclicFileFileNumber, recordNumber, numberOfRecords, responseData, false);
                        //writeToUiAppend(readResult, printData("readFileData", readFileData));
                        writeToUiAppend(readResult, "record " + i + " : " + new String(readFileData, StandardCharsets.UTF_8));
                        readFileStatus = returnStatusBytes(readFileData);
                        if (readFileStatus[1] != (byte) 0xAF) readData = false;
                    }
                }
            }
        });

        btn14.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // change application key
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "changeAppKey");

                // this is the manual way
                // it is NOT WORKING because of missing encryption implementation in changeKey method
/*
                // select application
                // select the application
                byte[] responseData = new byte[2];
                boolean success = selectApplicationDes(readResult, AID_DesLog, responseData);
                writeToUiAppend(readResult, "changeAppKey selectApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // note: the access key settings for this application is 0x0F see M075031_desfire.pdf pages 33, 34 + 35
                // createApplicationDes:
                // byte applicationMasterKeySettings = (byte) 0x0f; - the leftmost bits are '0' so it is the appMasterKey ('00') that has tto get used for authorization
                boolean authenticateSuccess = authenticateApplicationDes(readResult, AID_DesLog_Key0_Number, AID_DesLog_Key0, responseData);
                writeToUiAppend(readResult, "authenticateApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateSuccess) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }

                // change the key
                responseData = new byte[2];
                // note: the access key settings for this application is 0x0F see M075031_desfire.pdf pages 33, 34 + 35
                // createApplicationDes:
                // byte applicationMasterKeySettings = (byte) 0x0f; - the leftmost bits are '0' so it is the appMasterKey ('00') that has tto get used for authorization
                //boolean changeKeySuccess = changeApplicationKeyDes(readResult, AID_DesLog_Key2_Number, AID_DesLog_Key2_New, AID_DesLog_Key2, responseData);
                boolean changeKeySuccess = changeApplicationKeyDes(readResult, AID_DesLog_Key2_Number, AID_DesLog_Key2, AID_DesLog_Key2_New, responseData);
                writeToUiAppend(readResult, "changeKey success: " + success + " with response: " + Utils.bytesToHex(responseData));
                if (!changeKeySuccess) {
                    writeToUiAppend(readResult, "the changeKey was not successful, aborted");
                    return;
                }
*/


                // for key changing use DESFireEV1.java implementation
                DESFireEV1 desFireEV1 = new DESFireEV1();
                try {
                    // set adapter
                    //desFireEV1.setAdapter(defaultIsoDepAdapter);
                    desFireEV1.setAdapter(desFireAdapter);

                    // select an application
                    boolean sucSelectApplication = desFireEV1.selectApplication(AID_DesLog);
                    writeToUiAppend(readResult, "sucSelectApplication: " + sucSelectApplication);

                    // note: the access key settings for this application is 0x0F see M075031_desfire.pdf pages 33, 34 + 35
                    // createApplicationDes:
                    // byte applicationMasterKeySettings = (byte) 0x0f; - the leftmost bits are '0' so it is the appMasterKey ('00') that has tto get used for authorization

                    // authenticate with key 0
                    boolean sucAuthenticateAid = desFireEV1.authenticate(AID_DesLog_Key0, AID_DesLog_Key0_Number, KeyType.DES);
                    writeToUiAppend(readResult, "suc in auth for " + sucAuthenticateAid);

                    // authenticate with key 1
                    //sucAuthenticateAid = desFireEV1.authenticate(applicationIdentifier_DesLog_Key1, applicationIdentifier_DesLog_Key1_Number, DESFireEV1.DesfireKeyType.DES);
                    //writeToUiAppend(readResult, "suc in auth for " + sucAuthenticateAid);

                    // authenticate with key 2
                    //boolean sucAuthenticateAid = desFireEV1.authenticate(applicationIdentifier_DesLog_Key2_NEW, applicationIdentifier_DesLog_Key2_Number, DESFireEV1.DesfireKeyType.DES);
                    //writeToUiAppend(readResult, "suc in auth for " + sucAuthenticateAid);

                    // change the key
                    // this is the real key used without any keyVersion bits. The new key is automatically stripped off the version bytes but not the old key
                    setKeyVersion(AID_DesLog_Key2_New, 0, AID_DesLog_Key2_New.length, (byte) 0x00);
                    boolean sucChange = desFireEV1.changeKey(AID_DesLog_Key2_Number, KeyType.DES, AID_DesLog_Key2_New, AID_DesLog_Key2);
                    //boolean sucChange =  desFireEV1.changeKey(applicationIdentifier_DesLog_Key2_Number, DESFireEV1.DesfireKeyType.DES, applicationIdentifier_DesLog_Key2, applicationIdentifier_DesLog_Key2_New);

                    // this is the real key used without any keyVersion bits. The new key is automatically stripped off the version bytes but not the old key
                    setKeyVersion(AID_DesLog_Key2_New, 0, AID_DesLog_Key2_New.length, (byte) 0x00);
                    //boolean sucChange =  desFireEV1.changeKey(AID_DesLog_Key2_Number, DESFireEV1.DesfireKeyType.DES, AID_DesLog_Key2, AID_DesLog_Key2_New);

                    writeToUiAppend(readResult, "sucChangeKey: " + sucChange);
                    // public boolean authenticate(byte[] key, byte keyNo, DesfireKeyType type) throws IOException {
                    //boolean suc = desFireEV1.authenticate(applicationIdentifier_DesLog_key1, (byte) 0x01, DESFireEV1.DesfireKeyType.DES);
                    //writeToUiAppend(readResult, "suc in auth for " + suc);

                    // set the keyVersion to 0 for a given key
                    //byte[] applicationIdentifier_DesLog_Key2_New_keyVersion0 = AID_DesLog_Key2_New.clone();
                    //writeToUiAppend(readResult, printData("applicationIdentifier_DesLog_Key2_New_keyVersion0 old", applicationIdentifier_DesLog_Key2_New_keyVersion0));
                    //setKeyVersion(applicationIdentifier_DesLog_Key2_New_keyVersion0, 0, applicationIdentifier_DesLog_Key2_New_keyVersion0.length, (byte) 0x00);
                    //writeToUiAppend(readResult, printData("applicationIdentifier_DesLog_Key2_New_keyVersion0 new", applicationIdentifier_DesLog_Key2_New_keyVersion0));

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "IOException: " + e.getMessage());
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "Exception: " + e.getMessage());
                    return;
                }
            }
        });

        btn15.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // clear cyclic file
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "clear cyclic file");

                // select application
                // select the application
                byte[] responseData = new byte[2];
                boolean success = selectApplicationDes(readResult, AID_DesLog, responseData);
                writeToUiAppend(readResult, "selectApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));

                // authenticate with key 1
                responseData = new byte[2];
                // note: the access key settings for this application is 0x0F see M075031_desfire.pdf pages 33, 34 + 35
                boolean authenticateSuccess = authenticateApplicationDes(readResult, AID_DesLog_Key1_Number, AID_DesLog_Key1, false, responseData);
                writeToUiAppend(readResult, "authenticateApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateSuccess) {
                    writeToUiAppend(readResult, "the authentication was not successful, aborted");
                    return;
                }

                // clear the file
                responseData = new byte[2];
                boolean clearCyclicFileSuccess = clearRecordFile(readResult, DesLogCyclicFileFileNumber, responseData);
                writeToUiAppend(readResult, "clearCyclicFile success: " + clearCyclicFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!clearCyclicFileSuccess) {
                    writeToUiAppend(readResult, "the clearCyclicFile was not successful, aborted");
                    return;
                }

                // don't forget to commit
                responseData = new byte[2];
                boolean commitSuccess = commitWriteToFile(readResult, responseData);
                writeToUiAppend(readResult, "commit success: " + commitSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!commitSuccess) {
                    writeToUiAppend(readResult, "commit was not successful, aborted");
                }

            }
        });

        btn16.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // generate bulk data
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "generate bulk data");

                // first select application 00 00 00
                byte[] responseData = new byte[2];
                responseData = new byte[2];
                boolean selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectMasterApplication success: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectMasterApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectMasterApplication was not successful, aborted");
                    return;
                }

                // authenticate
                responseData = new byte[2];
                boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, (byte) 0x00, AID_Master_Key0, false, responseData);
                writeToUiAppend(readResult, "authenticateMasterApplication success: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the authenticationMasterApplication was not successful, aborted");
                    return;
                }

                // generate 20 app ids
                for (int i = 0; i < 20; i++) {
                    byte[] aid = new byte[]{(byte) (0x00), (byte) 0x01, (byte) 0x02};
                    aid[0] = (byte) i;

                    // create the application
                    boolean createApplicationSuccess = createApplicationDes(readResult, aid, (byte) 0x02, responseData);
                    writeToUiAppend(readResult, "createApplication success: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
/*
                    // select the application
                    boolean selectApplicationSuccessL = selectApplicationDes(readResult, aid, responseData);
                    writeToUiAppend(readResult, "selectApplication success: " + selectApplicationSuccessL + " with response: " + Utils.bytesToHex(responseData));
*/
                    /*
                    // authenticate the application
                    // authenticate with key 1
                    responseData = new byte[2];
                    // note: the access key settings for this application is 0x0F see M075031_desfire.pdf pages 33, 34 + 35
                    boolean authenticateSuccess = authenticateApplicationDes(readResult, (byte) 0x01, new byte[8], responseData);
                    writeToUiAppend(readResult, "authenticateApplication success: " + authenticateSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!authenticateSuccess) {
                        writeToUiAppend(readResult, "the authentication was not successful, aborted");
                        return;
                    }

                     */
/*
                    // create the cyclic file
                    boolean createCyclicFileSuccess = createCyclicFile(readResult, (byte) 0x01, responseData);
                    writeToUiAppend(readResult, "createCyclicFile success: " + createCyclicFileSuccess + " with response: " + Utils.bytesToHex(responseData));
*/
                    /*
                    // write a commit
                    responseData = new byte[2];
                    boolean commitSuccess = writeToFileCommit(readResult, responseData);
                    writeToUiAppend(readResult, "commit success: " + commitSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!commitSuccess) {
                        writeToUiAppend(readResult, "commit was not successful, aborted");
                        return;
                    }
                     */
                }

                writeToUiAppend(readResult, "bulk generation finished");
            }
        });

        btn17.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // memory usage measures
            }
        });

        btn18.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // AES playground

                DESFireEV1 desfire = new DESFireEV1();
                try {

                    // set adapter
                    //desfire.setAdapter(defaultIsoDepAdapter);
                    desfire.setAdapter(desFireAdapter);

                    // select PICC (is selected by default but...)
                    boolean selectMasterApplicationSuccess = desfire.selectApplication(new byte[]{0x00, 0x00, 0x00});
                    writeToUiAppend(readResult, "selectMasterApplicationSuccess: " + selectMasterApplicationSuccess);
                    if (!selectMasterApplicationSuccess) {
                        writeToUiAppend(readResult, "selectMasterApplication NOT Success, aborted");
                        return;
                    }
                    // authenticate: assume default key with cipher AES
                    // for KeyType see com.github.skjolber.desfire.ev1.model.key.DESFireKeyType.java
                    // NONE(0), DES(1), TDES(2), TKTDES(3), AES(4);

                    //desfire.authenticate(new byte[16], (byte) 0x00, KeyType.AES);
                    //boolean authenticateMasterApplicationSuccess = desfire.authenticate(new byte[16], (byte) 0x00, DESFireEV1.DesfireKeyType.AES);
                    boolean authenticateMasterApplicationSuccess = desfire.authenticate(new byte[8], (byte) 0x00, KeyType.DES);
                    writeToUiAppend(readResult, "authenticateMasterApplicationSuccess: " + authenticateMasterApplicationSuccess);
                    if (!authenticateMasterApplicationSuccess) {
                        writeToUiAppend(readResult, "authenticateMasterApplication NOT Success, aborted");
                        return;
                    }

                    // getKeySettings
                    DesfireApplicationKeySettings keySettingsOrgDes = desfire.getKeySettings();
                    writeToUiAppend(readResult, "keySettings (Org/DES): " + keySettingsOrgDes.toString());
                    // keySettings (Org/DES): DesfireApplicationKeySettings [changeKeyAccessRights=0, configurationChangable=true, freeCreateAndDelete=true, freeDirectoryAccess=true, canChangeMasterKey=true, maxKeys=1, twoByteIdentifiers=false, type=TDES, settings=[15, 1]]

                    // create an application with AES keys
                    byte[] aid = Utils.hexStringToByteArray("b3b2b1");
                    byte applicationMasterKeySettings = (byte) 0x0f; // amks
                    byte[] aesKey = new byte[16];
                    byte[] desKey = new byte[8];
                    byte[] tkdesKey = new byte[24];
                    byte aesKeyNumber = (byte) 0x00;
                    byte numberOfKeys = (byte) 0x03; // 3 AES keys
                    byte fileNumber = (byte) 0x01;
                    //boolean createApplication = desfire.createApplication(aid, applicationMasterKeySettings, DESFireEV1.DesfireKeyType.AES, numberOfKeys);
                    //boolean createApplication = desfire.createApplication(aid, applicationMasterKeySettings, DESFireEV1.DesfireKeyType.TKTDES, numberOfKeys);
                    boolean createApplication = desfire.createApplication(aid, applicationMasterKeySettings, KeyType.DES, numberOfKeys);
                    writeToUiAppend(readResult, "createApplication: " + createApplication);

                    // select an application
                    boolean selectApplication = desfire.selectApplication(aid);
                    writeToUiAppend(readResult, "selectApplication: " + selectApplication);

                    // authenticate
                    //boolean auth = desfire.authenticate(aesKey, aesKeyNumber, DESFireEV1.DesfireKeyType.AES);
                    //boolean auth = desfire.authenticate(tkdesKey, aesKeyNumber, DESFireEV1.DesfireKeyType.TKTDES);
                    boolean auth = desfire.authenticate(desKey, aesKeyNumber, KeyType.DES);

                    writeToUiAppend(readResult, "authenticateApplication: " + auth);

                    // create a standard file

                    byte communicationSettings = (byte) 0x00; // plain communication without any encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
                    byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
                    byte accessRightsRW = (byte) 0x12; // Read Access & Write Access // read with key 1, write with key 2
                    byte[] fileSize = new byte[]{(byte) 0x20, (byte) 0xf00, (byte) 0x00}; // 32 bytes
                    byte[] payloadStandardFile = new byte[7];
                    payloadStandardFile[0] = fileNumber; // fileNumber
                    payloadStandardFile[1] = communicationSettings;
                    payloadStandardFile[2] = accessRightsRwCar;
                    payloadStandardFile[3] = accessRightsRW;
                    System.arraycopy(fileSize, 0, payloadStandardFile, 4, 3);
                    /*
                     * @param payload	7-byte array, with the following content:
                     * 					<br>file number (1 byte),
                     * 					<br>communication settings (1 byte),
                     * 					<br>access rights (2 bytes),
                     * 					<br>file size (3 bytes)
                     */
                    //writeToUiAppend(readResult, printData("payloadStandardFile", payloadStandardFile));
                    //boolean createStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    //writeToUiAppend(readResult, "createStandardFile Success: " + createStandardFile);

                    // create cyclic value file
                    /*
                     * 					<br>file number (1 byte),
                     * 					<br>communication settings (1 byte),
                     * 					<br>access rights (2 bytes: RW||CAR||R||W),
                     * 					<br>size of a single record size (3 bytes LSB),
                     * 					<br>maximum amount of records (3 bytes LSB)
                     */
                    byte[] numberOfRecords = new byte[]{(byte) 0x04, (byte) 0xf00, (byte) 0x00}; // 4 records
                    byte[] payloadCyclicValueFile = new byte[10];
                    payloadCyclicValueFile[0] = fileNumber; // fileNumber
                    payloadCyclicValueFile[1] = communicationSettings;
                    payloadCyclicValueFile[2] = accessRightsRwCar;
                    payloadCyclicValueFile[3] = accessRightsRW;
                    System.arraycopy(fileSize, 0, payloadCyclicValueFile, 4, 3);
                    System.arraycopy(numberOfRecords, 0, payloadCyclicValueFile, 7, 3);
                    writeToUiAppend(readResult, printData("payloadCyclicValueFile", payloadCyclicValueFile));
                    boolean createCyclicValueFile = desfire.createCyclicRecordFile(payloadCyclicValueFile);
                    writeToUiAppend(readResult, "createCyclicValueFile Success: " + createCyclicValueFile);


                    // write data to standard file
                    byte[] dataByte = "hello".getBytes(StandardCharsets.UTF_8); // 5 bytes long
                    byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning
                    byte lengthOfData = (byte) (dataByte.length & 0xFF);

                    byte[] payloadWriteData = new byte[7 + dataByte.length]; // 7 + length of data
                    payloadWriteData[0] = (byte) 0x01; // fileNumber
                    System.arraycopy(offset, 0, payloadWriteData, 1, 3);
                    payloadWriteData[4] = lengthOfData;
                    //payloadStandardFile[5] = 0; // is 0x00
                    //payloadStandardFile[6] = 0; // is 0x00
                    System.arraycopy(dataByte, 0, payloadWriteData, 7, dataByte.length);
                    /*
                     * @param payload	a byte array with the following contents:
                     * 					<br>file number (1 byte),
                     * 					<br>offset within the file being written (3 bytes LSB),
                     * 					<br>length of the data (3 byte LSB),
                     * 					<br>the data (1+ bytes)
                     */
                    /*
                    writeToUiAppend(readResult, printData("payloadWriteData", payloadWriteData));
                    boolean writeData = desfire.writeData(payloadWriteData);
                    writeToUiAppend(readResult, "writeToStandardFile Success: " + writeData);
                    */

                    // write to cyclic value file, identical payload
                    /*
                     * 					<br>file number (1 byte),
                     * 					<br>offset within the record (3 bytes LSB),
                     * 					<br>length of the data to be written (3 bytes LSB),
                     * 					<br>the data (1+ bytes)
                     */
/*
                    writeToUiAppend(readResult, printData("payloadCyclicValueData", payloadWriteData));
                    boolean writeCyclicValue = desfire.writeRecord(payloadWriteData);
                    writeToUiAppend(readResult, "writeCyclicValue Success: " + writeCyclicValue);

 */
                    // payloadCyclicValueData length: 12 data: 0100000005000068656c6c6f
// my data writeFileParameters length: 37 data:                040000001e0000456e7472792066726f6d20323032332e30342e32352031363a31373a3034

/*
payloadCyclicValueFile    length: 10 data: 01000012200000040000
*** DESFireEV1 transmit command: 90c000000a0100001220000004000000
 */



/*

                    // commit
                    boolean commitTransaction = desfire.commitTransaction();
                    writeToUiAppend(readResult, "commitTransaction: " + commitTransaction);

                    byte[] readData = desfire.readData(fileNumber, 0, 10);
                    writeToUiAppend(readResult, printData("readData", readData));
                    writeToUiAppend(readResult, "readData: " + new String(readData, StandardCharsets.UTF_8));
*/
/*
                    // create application AES cipher and two application keys
                    writeToUiAppend(readResult, "create application with AES authentication");
                    byte[] APPLICATION_ID = new byte[] {0x09, 0x05, 0x07};
                    boolean createApplicationSuccess = desfire.createApplication(APPLICATION_ID, (byte) 0x0F, DESFireEV1.DesfireKeyType.AES, (byte) 0x02);
                    writeToUiAppend(readResult, "createApplicationSuccess: " + createApplicationSuccess);

                    // authenticate the new application
                    // authenticate inside application with key 0x00 and cipher 3K3DES
                    boolean authenticateApplicationSuccess = desfire.authenticate(new byte[16], (byte) 0x00, DESFireEV1.DesfireKeyType.AES);
                    writeToUiAppend(readResult, "authenticateApplicationSuccess: " + authenticateApplicationSuccess);
                    if (!authenticateApplicationSuccess) {
                        writeToUiAppend(readResult,"authenticateApplication NOT Success, aborted");
                        return;
                    }

                    // select application
                    boolean selectApplicationSuccess = desfire.selectApplication(APPLICATION_ID);
                    writeToUiAppend(readResult, "selectApplicationSuccess: " + selectApplicationSuccess);
                    if (!selectApplicationSuccess) {
                        writeToUiAppend(readResult,"selectApplication NOT Success, aborted");
                        return;
                    }


                    writeToUiAppend(readResult, "creation of a TKDES encrypted application done");

 */

                    // write to cyclic file with own method
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "write to Cyclic Record File own");
                    byte[] responseData = new byte[2];
                    boolean writeCyc = writeToCyclicFile(readResult, fileNumber, responseData);
                    writeToUiAppend(readResult, "writeCyc: " + writeCyc + " response: " + Utils.bytesToHex(responseData));
                    boolean writeCycCommit = commitWriteToFile(readResult, responseData);
                    writeToUiAppend(readResult, "writeCycCommit: " + writeCycCommit + " response: " + Utils.bytesToHex(responseData));

                    // write to cyclic file desfire
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "write to Cyclic Record File DesfireEV1");
                    //byte[] writeCycPayload = new byte[1];
                    byte[] offsetZero = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
                    byte[] dataLength;
                    String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
                    int contentLengthInt = contentString.length();
                    // todo be more universal with this. The created record size is 32 so this data is fitting into one record
                    byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
                    byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
                    byte[] writeFileParameters = new byte[(contentLengthInt + 7)];
                    writeFileParameters[0] = fileNumber;
                    System.arraycopy(offsetZero, 0, writeFileParameters, 1, 3);
                    System.arraycopy(contentLength, 0, writeFileParameters, 4, 3);
                    System.arraycopy(content, 0, writeFileParameters, 7, contentLengthInt);
                    writeToUiAppend(readResult, printData("writeFileParameters DesfireEV1", writeFileParameters));
                    boolean writeCycDesfire = desfire.writeRecord(writeFileParameters);
                    if (writeCycDesfire) {
                        writeToUiAppend(readResult, "writeCycDesfire was successful");
                    } else {
                        writeToUiAppend(readResult, "writeCycDesfire was NOT successful");
                    }


                    // now desfire method to read
                    /*
                    byte[] dataRead = desfire.readData(fileNumber, 0, 0);
                    writeToUiAppend(readResult, printData("dataRead", dataRead));
                    if (dataRead != null) {
                        writeToUiAppend(readResult, new String(dataRead, StandardCharsets.UTF_8));
                    }

                     */
                    // *** read comm: 90 bd 0000 07 01 00000000002000
                    // my manua comm: 90 bb 0000 07 04 04000001000000

                    // now desfire method to read second try
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "write to Cyclic Record File DesfireEV1");
                    byte[] dataRead2 = desfire.readRecords(fileNumber, 0, 1);
                    writeToUiAppend(readResult, printData("dataRead2", dataRead2));
                    if (dataRead2 != null) {
                        writeToUiAppend(readResult, new String(dataRead2, StandardCharsets.UTF_8));
                    }
                    // read comm:     90 bb 0000 07 01 000000000020 00
                    // 1 record:      90 BB 0000 07 01 000000000001 00
                    // my manua comm: 90 bb 0000 07 04 040000010000 00


                    /// my method
                    // define some data
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "write to Cyclic Record File own");
                    byte[] recordNumber = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // record 0 is the youngest record
                    byte[] numberOfRecordsMy = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x00}; // read just one record
                    byte[] readDataMy = readFromCyclicFile(readResult, fileNumber, recordNumber, numberOfRecordsMy, responseData, true);
                    writeToUiAppend(readResult, printData("readDataMy", readDataMy));

                    byte[] numberOfRecordsMy2 = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x20}; // read all records // BE = Boundary error
                    byte[] readDataMy2 = readFromCyclicFile(readResult, fileNumber, recordNumber, numberOfRecordsMy2, responseData, true);
                    writeToUiAppend(readResult, printData("readDataMy2", readDataMy2));

                    // get the file settings for the new file
                    responseData = new byte[2];
                    byte[] fileSettingsRecord = getFileSettingsRecord(readResult, fileNumber, responseData);
                    writeToUiAppend(readResult, printData("fileSettingsRecord", fileSettingsRecord) + " with response: " + Utils.bytesToHex(responseData));
                    if (!checkResponse(fileSettingsRecord)) {
                        writeToUiAppend(readResult, "the fileSettingsRecord was not successful, aborted");
                        return;
                    }
                    byte[] fileSettingsData = Arrays.copyOf(fileSettingsRecord, fileSettingsRecord.length - 2);
                    if (fileSettingsData.length == 13) {
                        FileSettingRecordModel fsrm = new FileSettingRecordModel(fileNumber, fileSettingsData);
                        writeToUiAppend(readResult, fsrm.dumpFileSizes());
                    }

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "IOException: " + e.getMessage());
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "Exception: " + e.getMessage());
                    writeToUiAppend(readResult, "Stack: " + Arrays.toString(e.getStackTrace()));
                    System.out.println(Arrays.toString(e.getStackTrace()));
                }


            }
        });

        btn19.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // prepare card for AES

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "preparing the card for AES usage (format, change masterKey to aes");

                DESFireEV1 desfire = new DESFireEV1();
                try {

                    // set adapter
                    //desfire.setAdapter(defaultIsoDepAdapter);
                    desfire.setAdapter(desFireAdapter);

                    byte[] aid = Utils.hexStringToByteArray("c3c2c1");
                    byte[] desKey = new byte[8];
                    byte[] aesKey = new byte[16];
                    byte aesKeyNumberRW = 0;
                    byte aesKeyNumberR = 1;
                    byte aesKeyNumberW = 2;
                    byte numberOfKeysDes = (byte) 0x03; // 3 DES keys
                    byte numberOfKeysAes = (byte) 0x83; // 3 AES keys

                    byte aesFileNumberStandard = (byte) 0x01;
                    byte aesFileNumberValue = (byte) 0x02;
                    byte aesFileNumberCircle = (byte) 0x03;
                    byte[] dataToWrite = "some data".getBytes(StandardCharsets.UTF_8);

                    // select PICC (is selected by default but...)
                    boolean selectMasterApplicationSuccess = desfire.selectApplication(new byte[]{0x00, 0x00, 0x00});
                    writeToUiAppend(readResult, "selectMasterApplicationSuccess: " + selectMasterApplicationSuccess);
                    if (!selectMasterApplicationSuccess) {
                        writeToUiAppend(readResult, "selectMasterApplication NOT Success, aborted");
                        return;
                    }

                    // auth
                    boolean authenticateMasterApplicationSuccess = desfire.authenticate(desKey, (byte) 0x00, KeyType.DES);
                    //boolean authenticateMasterApplicationSuccess = desfire.authenticate(new byte[8], (byte) 0x00, DESFireEV1.DesfireKeyType.DES);
                    writeToUiAppend(readResult, "authenticateMasterApplicationSuccess: " + authenticateMasterApplicationSuccess);
                    if (!authenticateMasterApplicationSuccess) {
                        writeToUiAppend(readResult, "authenticateMasterApplication NOT Success, aborted");
                        return;
                    }

                    // create application
                    byte[] responseData = new byte[2];
                    //boolean createApplication = createApplicationDes(readResult, aid, numberOfKeys, responseData);
                    boolean createApplication = createApplicationAes(readResult, aid, numberOfKeysAes, responseData); // numberOfKeysAes is 0x8x - 8 means AES, 4 means TKTDES

                    writeToUiAppend(readResult, "createApplication: " + createApplication + " response: " + Utils.bytesToHex(responseData));

                    // select this application
                    responseData = new byte[2];
                    boolean success = selectApplicationDes(readResult, aid, responseData);
                    writeToUiAppend(readResult, "selectApplication success: " + success + " with response: " + Utils.bytesToHex(responseData));

                    // authenticate with desfire method
                    // authenticate inside application with key 0x00 and cipher 3K3DES
                    boolean authenticateApplicationSuccess = desfire.authenticate(aesKey, aesKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "authenticateApplicationSuccess: " + authenticateApplicationSuccess);
                    if (!authenticateApplicationSuccess) {
                        writeToUiAppend(readResult, "authenticateApplication NOT Success, aborted");
                        return;
                    }

                    // create the standard file
                    responseData = new byte[2];
                    boolean createStandardFileSuccess = createStandardFile(readResult, aesFileNumberStandard, responseData);
                    writeToUiAppend(readResult, "createStandardFile result: " + createStandardFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!createStandardFileSuccess) {
                        writeToUiAppend(readResult, "the createStandardFile was not successful, aborted");
                        return;
                    }

                    // write to standard file
                    responseData = new byte[2];
                    boolean writeStandardFileSuccess = writeToStandardFile(readResult, aesFileNumberStandard, dataToWrite, responseData);
                    writeToUiAppend(readResult, "writeStandardFile result: " + writeStandardFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!writeStandardFileSuccess) {
                        writeToUiAppend(readResult, "the writeStandardFile was not successful, aborted");
                        return;
                    }


                    // get the file settings for the new file
                    responseData = new byte[2];
                    byte[] fileSettingsRecord = getFileSettingsRecord(readResult, DesStandardFileFileNumber1, responseData);
                    writeToUiAppend(readResult, printData("fileSettingsRecord", fileSettingsRecord) + " with response: " + Utils.bytesToHex(responseData));
                    if (!checkResponse(fileSettingsRecord)) {
                        writeToUiAppend(readResult, "the fileSettingsRecord was not successful, aborted");
                        return;
                    }
                    byte[] fileSettingsData = Arrays.copyOf(fileSettingsRecord, fileSettingsRecord.length - 2);


                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "IOException: " + e.getMessage());
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "Exception: " + e.getMessage());
                    writeToUiAppend(readResult, "Stack: " + Arrays.toString(e.getStackTrace()));
                    System.out.println(Arrays.toString(e.getStackTrace()));
                }

                /*
                code from https://github.com/andrade/nfcjlib/blob/master/src/nfcjlib/sample/MDF1.java

                DESFireEV1.DesfireKeyType applicationCipherType = DESFireEV1.DesfireKeyType.TKTDES;

                byte[] skey, appKey, aid, payload;
                byte amks, nok, fileNo1, fileNo2, fileNo3, cs, ar1, ar2;
                Integer val;
                nfcjlib.core.DESFireEV1 desfire = new nfcjlib.core.DESFireEV1();


                // authenticate with PICC master key (AES, 16 bytes cleared)
                try {

                    skey = desfire.authenticate(new byte[16], (byte) 0x00, DESFireEV1.DesfireKeyType.AES);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                if (skey == null) {
                    System.out.println("Session key is null");
                    return;
                }
                System.out.println("The secret  key is " + Utils.bytesToHex((new byte[16])));
                System.out.println("The session key is " + Utils.bytesToHex((skey)));

                // format PICC
                try {
                    if (!desfire.formatPICC())
                        return;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                // create an application
                aid = new byte[] {0x01, 0x02, 0x03};
                amks = 0x0F;
                switch (applicationCipherType) {
                    case DES:
                        nok = 0x05;
                        appKey = new byte[8];
                        break;
                    case TKTDES:
                        nok = 0x45;
                        appKey = new byte[24];
                        break;
                    case AES:
                        nok = (byte) 0x85;
                        appKey = new byte[16];
                        break;
                    default:
                        return;
                }
                if (!desfire.createApplication(aid, amks, nok))
                    return;

                // select the application created
                if(!desfire.selectApplication(aid))
                    return;

                // authenticate with the 3rd application key (default one)
                // (RW is set to 0x3: grants access to credit/getValue operations)
                skey = desfire.authenticate(appKey, (byte) 0x03, applicationCipherType);
                if (skey == null) {
                    System.out.println("Session key is null (application)");
                    return;
                }
                System.out.println("The secret  key is " + Dump.hex(appKey));
                System.out.println("The session key is " + Dump.hex(skey));

                // create a value file in the new application: fileNo=4, cs=0
                fileNo1 = 0x04;
                cs = 0x00;
                ar1 = 0x30;  // RW|CAR
                ar2 = 0x00;  // R|W
                payload = new byte[] {
                        fileNo1, cs, ar1, ar2,
                        10, 0, 0, 0,  // lower limit: 10
                        90, 0, 0, 0,  // upper limit: 90
                        50, 0, 0, 0,  // initial value: 50
                        0  // limitedCredit operation disabled
                };
                if (!desfire.createValueFile(payload))
                    return;

                // create a value file in the new application: fileNo=5, cs=1
                fileNo2 = 0x05;
                cs = 0x01;
                ar1 = 0x30;  // RW|CAR
                ar2 = 0x00;  // R|W
                payload = new byte[] {
                        fileNo2, cs, ar1, ar2,
                        10, 0, 0, 0,  // lower limit: 10
                        90, 0, 0, 0,  // upper limit: 90
                        50, 0, 0, 0,  // initial value: 50
                        0  // limitedCredit operation disabled
                };
                if (!desfire.createValueFile(payload))
                    return;

                // create a value file in the new application: fileNo=6, cs=3
                fileNo3 = 0x06;
                cs = 0x03;
                ar1 = 0x30;  // RW|CAR
                ar2 = 0x00;  // R|W
                payload = new byte[] {
                        fileNo3, cs, ar1, ar2,
                        10, 0, 0, 0,  // lower limit: 10
                        90, 0, 0, 0,  // upper limit: 90
                        50, 0, 0, 0,  // initial value: 50
                        0  // limitedCredit operation disabled
                };
                if (!desfire.createValueFile(payload))
                    return;


                // increase the value stored in the last value file (twice!):
                // - requires preceding authentication with RW key (done); and a
                // - commit transaction after the credit operation
                if (!desfire.credit(fileNo1, 7))
                    return;
                if (!desfire.credit(fileNo1, 7))
                    return;
                if (!desfire.commitTransaction())
                    return;
                if (!desfire.credit(fileNo2, 7))
                    return;
                if (!desfire.credit(fileNo2, 7))
                    return;
                if (!desfire.commitTransaction())
                    return;
                if (!desfire.credit(fileNo3, 7))
                    return;
                if (!desfire.credit(fileNo3, 7))
                    return;
                if (!desfire.commitTransaction())
                    return;

                // read the stored value ( = initial value + credit + credit )
                val = desfire.getValue(fileNo1);
                if (val == null)
                    return;
                System.out.println("The stored value (fileNo=4, cs=0) is " + val.intValue());
                val = desfire.getValue(fileNo2);
                if (val == null)
                    return;
                System.out.println("The stored value (fileNo=5, cs=1) is " + val.intValue());
                val = desfire.getValue(fileNo3);
                if (val == null)
                    return;
                System.out.println("The stored value (fileNo=6, cs=3) is " + val.intValue());

                // tear down the connection with the card
                if (!desfire.disconnect())
                    return;

                System.out.println("success.");
                 */
            }
        });

        btn20.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // auth with AES keys

                byte[] desAid = Utils.hexStringToByteArray("d3d2d1");
                byte[] desKey = new byte[8];
                byte desKeyNumberRW = 0;
                byte desKeyNumberR = 1;
                byte desKeyNumberW = 2;
                byte desNumberOfKeys = (byte) 0x03; // 3 DES keys
                byte desFileNumberCycle = (byte) 0x02;
                byte[] dataToWrite = "some data".getBytes(StandardCharsets.UTF_8);

                // first we setup a des-key secured application
                byte[] responseData = new byte[2];

                // select the master file application
                responseData = new byte[2];
                boolean selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectMasterApplication result: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, AID_Master_Key0_Number, AID_Master_Key0, false, responseData);
                writeToUiAppend(readResult, "authenticateMasterApplication result: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the authenticationMaster was not successful, aborted");
                    return;
                }

                // create the new application
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean createApplicationSuccess = createApplicationDes(readResult, desAid, desNumberOfKeys, responseData);
                writeToUiAppend(readResult, "createApplication result: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createApplicationSuccess) {
                    writeToUiAppend(readResult, "the createApplication was not successful, aborted");
                    //return;
                }

                // select the application
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, desAid, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateDesApplicationSuccess = authenticateApplicationDes(readResult, desKeyNumberRW, desKey, false, responseData);
                writeToUiAppend(readResult, "authenticateDesApplication result: " + authenticateDesApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateDesApplicationSuccess) {
                    writeToUiAppend(readResult, "the authenticateDesApplication was not successful, aborted");
                    return;
                }

                // create the cyclic file
                responseData = new byte[2];
                boolean createCyclicFileSuccess = createCyclicFile(readResult, desFileNumberCycle, responseData);
                writeToUiAppend(readResult, "createCyclicFile success: " + createCyclicFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createCyclicFileSuccess) {
                    writeToUiAppend(readResult, "createCyclicFile was not successful, aborted");
                    //return;
                }

                // write to the cyclic file
                responseData = new byte[2];
                boolean writeToCyclicFileSuccess = writeToCyclicFile(readResult, desFileNumberCycle, responseData);
                writeToUiAppend(readResult, "writeToCyclicFile success: " + writeToCyclicFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeToCyclicFileSuccess) {
                    writeToUiAppend(readResult, "writeToCyclicFile was not successful, aborted");
                    //return;
                }
                // commit in cyclic file
                responseData = new byte[2];
                boolean writeToFileCommitSuccess = commitWriteToFile(readResult, responseData);
                writeToUiAppend(readResult, "writeToFileCommit success: " + writeToFileCommitSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeToFileCommitSuccess) {
                    writeToUiAppend(readResult, "writeToFileCommit was not successful, aborted");
                    //return;
                }

                /**
                 * part for aes application
                 */

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "same workflow for AES keys");

                byte[] aesAid = Utils.hexStringToByteArray("d3d2d7");
                byte[] aesKey = new byte[16];
                byte aesKeyNumberRW = 0;
                byte aesKeyNumberR = 1;
                byte aesKeyNumberW = 2;
                byte aesNumberOfKeys = (byte) 0x83; // 3 AES keys
                byte aesFileNumberCycle = (byte) 0x02;

                // select the master file application
                responseData = new byte[2];
                selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectMasterApplication result: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                authenticateMasterSuccess = authenticateApplicationDes(readResult, AID_Master_Key0_Number, AID_Master_Key0, false, responseData);
                writeToUiAppend(readResult, "authenticateMasterApplication result: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the authenticationMaster was not successful, aborted");
                    return;
                }

                // create the new application
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                createApplicationSuccess = createApplicationDes(readResult, aesAid, aesNumberOfKeys, responseData);
                writeToUiAppend(readResult, "createApplication result: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createApplicationSuccess) {
                    writeToUiAppend(readResult, "the createApplication was not successful, aborted");
                    //return;
                }

                // select the application
                responseData = new byte[2];
                selectApplicationSuccess = selectApplicationDes(readResult, aesAid, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateAesApplicationSuccess = authenticateApplicationAes(readResult, aesKeyNumberRW, aesKey, true, responseData);
                writeToUiAppend(readResult, "authenticateAesApplication result: " + authenticateAesApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateAesApplicationSuccess) {
                    writeToUiAppend(readResult, "the authenticateAesApplication was not successful, aborted");
                    //return;
                }

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "*** authenticate the application using DESFireEV1 method ***");
                boolean authenticateAesApplicationDfSuccess = false;
                try {
                    authenticateAesApplicationDfSuccess = authenticate(aesKey, aesKeyNumberRW, KeyType.AES);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                writeToUiAppend(readResult, "authenticateAesApplicationDf result: " + authenticateAesApplicationDfSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateAesApplicationDfSuccess) {
                    writeToUiAppend(readResult, "the authenticateAesApplicationDf was not successful, aborted");
                    //return;
                }

                // create the cyclic file
                responseData = new byte[2];
                createCyclicFileSuccess = createCyclicFile(readResult, aesFileNumberCycle, responseData);
                writeToUiAppend(readResult, "createCyclicFile success: " + createCyclicFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createCyclicFileSuccess) {
                    writeToUiAppend(readResult, "createCyclicFile was not successful, aborted");
                    //return;
                }

                // write to the cyclic file
                responseData = new byte[2];
                writeToCyclicFileSuccess = writeToCyclicFile(readResult, aesFileNumberCycle, responseData);
                writeToUiAppend(readResult, "writeToCyclicFile success: " + writeToCyclicFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeToCyclicFileSuccess) {
                    writeToUiAppend(readResult, "writeToCyclicFile was not successful, aborted");
                    //return;
                }
                // commit in cyclic file
                responseData = new byte[2];
                writeToFileCommitSuccess = commitWriteToFile(readResult, responseData);
                writeToUiAppend(readResult, "writeToFileCommit success: " + writeToFileCommitSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeToFileCommitSuccess) {
                    writeToUiAppend(readResult, "writeToFileCommit was not successful, aborted");
                    //return;
                }

            }
        });

        btn21.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // auth with AES keys but encrypted

                // first we setup a des-key secured application
                byte[] responseData = new byte[2];

                /**
                 * part for aes application
                 */

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "same workflow for AES keys");

                byte[] aesAid = Utils.hexStringToByteArray("e3e2e7");
                byte[] aesKey = new byte[16];
                byte aesKeyNumberRW = 0;
                byte aesKeyNumberR = 1;
                byte aesKeyNumberW = 2;
                byte aesNumberOfKeys = (byte) 0x83; // 3 AES keys
                byte aesFileNumberCycle = (byte) 0x02;

                // select the master file application
                responseData = new byte[2];
                boolean selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectMasterApplication result: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, AID_Master_Key0_Number, AID_Master_Key0, false, responseData);
                writeToUiAppend(readResult, "authenticateMasterApplication result: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the authenticationMaster was not successful, aborted");
                    return;
                }

                // create the new application
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean createApplicationSuccess = createApplicationDes(readResult, aesAid, aesNumberOfKeys, responseData);
                writeToUiAppend(readResult, "createApplication result: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createApplicationSuccess) {
                    writeToUiAppend(readResult, "the createApplication was not successful, aborted");
                    //return;
                }

                // select the application
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, aesAid, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }
/*
                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateAesApplicationSuccess = authenticateApplicationAes(readResult, aesKeyNumberRW, aesKey, true, responseData);
                writeToUiAppend(readResult, "authenticateAesApplication result: " + authenticateAesApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateAesApplicationSuccess) {
                    writeToUiAppend(readResult, "the authenticateAesApplication was not successful, aborted");
                    //return;
                }
*/


  /*
                // create the cyclic file - here with encrypted communication
                responseData = new byte[2];
                boolean createCyclicFileSuccess = createCyclicFileEncryptedCommunication(readResult, aesFileNumberCycle, responseData);
                writeToUiAppend(readResult, "createCyclicFile success: " + createCyclicFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createCyclicFileSuccess) {
                    writeToUiAppend(readResult, "createCyclicFile was not successful, aborted");
                    //return;
                }
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
/*
                // write to the cyclic file with encrypted data
                responseData = new byte[2];
                boolean writeToCyclicFileEncryptedSuccess = writeToCyclicFileEncrypted(readResult, aesFileNumberCycle, responseData);
                writeToUiAppend(readResult, "writeToCyclicFileEncrypted success: " + writeToCyclicFileEncryptedSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeToCyclicFileEncryptedSuccess) {
                    writeToUiAppend(readResult, "writeToCyclicFileEncrypted was not successful, aborted");
                    //return;
                }
                // commit in cyclic file
                responseData = new byte[2];
                boolean writeToFileCommitSuccess = commitWriteToFile(readResult, responseData);
                writeToUiAppend(readResult, "writeToFileCommit success: " + writeToFileCommitSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeToFileCommitSuccess) {
                    writeToUiAppend(readResult, "writeToFileCommit was not successful, aborted");
                    //return;
                }
*/
                DESFireEV1 desfire = new DESFireEV1();
                //desfire.setAdapter(defaultIsoDepAdapter);
                desfire.setAdapter(desFireAdapter);

                try {

                    // complete reading
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(readResult, "dfSelectMResult: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(new byte[8], (byte) 0, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthMReadResult: " + dfAuthM);

                    byte[] aesAidStandard = Utils.hexStringToByteArray("c3c2c9");
                    byte aesFileNumberStandard = (byte) 0x03;
                    byte applicationMasterKeySettings = (byte) 0x0f; // amks
                    boolean dfCreateStandard = desfire.createApplication(aesAidStandard, applicationMasterKeySettings, KeyType.AES, (byte) 3);
                    writeToUiAppend(readResult, "dfCreateStandardResult: " + dfCreateStandard);

                    boolean dfSelectStandard = desfire.selectApplication(aesAidStandard);
                    writeToUiAppend(readResult, "dfSelectStandardResult: " + dfSelectStandard);

                    boolean dfAuthStandard = desfire.authenticate(aesKey, aesKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthReadStandardResult: " + dfAuthStandard);

                    byte communicationSettings = (byte) 0x03; // full encrypted
                    byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
                    byte accessRightsRW = (byte) 0x00; // Read Access & Write Access // read with key 0, write with key 0
                    byte[] fileSize = new byte[]{(byte) 0x20, (byte) 0xf00, (byte) 0x00}; // 32 bytes
                    byte[] payloadStandardFile = new byte[7];
                    payloadStandardFile[0] = aesFileNumberStandard; // fileNumber
                    payloadStandardFile[1] = communicationSettings;
                    payloadStandardFile[2] = accessRightsRwCar;
                    payloadStandardFile[3] = accessRightsRW;
                    System.arraycopy(fileSize, 0, payloadStandardFile, 4, 3);
                    writeToUiAppend(readResult, printData("payloadStandardFile", payloadStandardFile));
                    boolean dfCreateStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(readResult, "dfCreateStandardFileResult: " + dfCreateStandardFile);

                    // auh ?

                    // byte[] payloadWriteData;
                    byte[] dataByte = "hello".getBytes(StandardCharsets.UTF_8); // 5 bytes long
                    byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning
                    byte lengthOfData = (byte) (dataByte.length & 0xFF);
                    byte[] payloadWriteData = new byte[7 + dataByte.length]; // 7 + length of data
                    payloadWriteData[0] = (byte) aesFileNumberStandard; // fileNumber
                    System.arraycopy(offset, 0, payloadWriteData, 1, 3);
                    payloadWriteData[4] = lengthOfData;
                    //payloadStandardFile[5] = 0; // is 0x00
                    //payloadStandardFile[6] = 0; // is 0x00
                    System.arraycopy(dataByte, 0, payloadWriteData, 7, dataByte.length);
                    writeToUiAppend(readResult, printData("payloadWriteData", payloadWriteData));
                    boolean dfWriteStandard = desfire.writeData(payloadWriteData);
                    writeToUiAppend(readResult, "dfWriteStandardResult: " + dfWriteStandard);


                    // rough end
                    if (desfire != null) return;


                    boolean dfSelect = desfire.selectApplication(aesAid);
                    writeToUiAppend(readResult, "dfSelectResult: " + dfSelect);

                    boolean dfAuth = desfire.authenticate(aesKey, aesKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthReadResult: " + dfAuth);

                    DesfireFile fs = desfire.getFileSettings(aesFileNumberCycle);
                    writeToUiAppend(readResult, "fs: " + fs.toString());

/*
fs: RecordDesfireFile [recordSize=32, maxRecords=6, currentRecords=0, records=null, fileType=CYCLIC_RECORD_FILE,
communicationSettings=ENCIPHERED, readAccessKey=0, writeAccessKey=0, readWriteAccessKey=0, changeAccessKey=0, id=2]
 */

                    //writeToUiAppend(readResult, "kno: " + desfire.getKno());

                    // build payload for Cyclic Record
                    byte[] offsetZero = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
                    String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
                    int contentLengthInt = contentString.length();
                    // todo be more universal with this. The created record size is 32 so this data is fitting into one record
                    byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
                    byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
                    byte[] writeFileParameters = new byte[(contentLengthInt + 7)];
                    writeFileParameters[0] = aesFileNumberCycle;
                    System.arraycopy(offsetZero, 0, writeFileParameters, 1, 3);
                    System.arraycopy(contentLength, 0, writeFileParameters, 4, 3);
                    System.arraycopy(content, 0, writeFileParameters, 7, contentLengthInt);
                    writeToUiAppend(readResult, printData("writeCycleFileParameters DesfireEV1", writeFileParameters));

                    boolean dfWrite = desfire.writeRecord(writeFileParameters);
                    writeToUiAppend(readResult, "dfWrite: " + dfWrite);


                } catch (IOException e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                } catch (Exception e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                }




                /* using in MainActivity
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "*** authenticate the application using DESFireEV1 method ***");
                boolean authenticateAesApplicationDfSuccess = false;
                try {
                    //authenticateAesApplicationDfSuccess = authenticate(aesKey, aesKeyNumberRW, DESFireEV1.DesfireKeyType.AES);
                    authenticateAesApplicationDfSuccess =  authenticate(aesKey, aesKeyNumberRW, DESFireEV1.DesfireKeyType.AES);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                writeToUiAppend(readResult, "authenticateAesApplicationDf result: " + authenticateAesApplicationDfSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateAesApplicationDfSuccess) {
                    writeToUiAppend(readResult, "the authenticateAesApplicationDf was not successful, aborted");
                    //return;
                }

                 */



            }
        });

        btn22.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // auth with DES keys but unencrypted

                // first we setup a des-key secured application
                byte[] responseData = new byte[2];

                DESFireEV1 desfire = new DESFireEV1();
                //desfire.setAdapter(defaultIsoDepAdapter);
                desfire.setAdapter(desFireAdapter);

                try {

                    // complete reading
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(readResult, "dfSelectMResult: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(new byte[8], (byte) 0, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthMReadResult: " + dfAuthM);

                    byte[] desAidStandard = Utils.hexStringToByteArray("838281");
                    byte[] desKey = new byte[8];
                    byte desKeyNumberRW = (byte) 0;
                    byte desFileNumberStandard = (byte) 0x01;
                    byte desFileNumberCyclic = (byte) 0x02;
                    byte applicationMasterKeySettings = (byte) 0x0f; // amks
                    boolean dfCreateStandard = desfire.createApplication(desAidStandard, applicationMasterKeySettings, KeyType.DES, (byte) 3);
                    writeToUiAppend(readResult, "dfCreateStandardResult: " + dfCreateStandard);

                    boolean dfSelectStandard = desfire.selectApplication(desAidStandard);
                    writeToUiAppend(readResult, "dfSelectStandardResult: " + dfSelectStandard);

                    boolean dfAuthStandard = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthReadStandardResult: " + dfAuthStandard);

                    byte communicationSettings = (byte) 0x00; // plain
                    byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
                    byte accessRightsRW = (byte) 0x00; // Read Access & Write Access // read with key 0, write with key 0
                    byte[] fileSize = new byte[]{(byte) 0x20, (byte) 0xf00, (byte) 0x00}; // 32 bytes
                    byte[] payloadStandardFile = new byte[7];
                    payloadStandardFile[0] = desFileNumberStandard; // fileNumber
                    payloadStandardFile[1] = communicationSettings;
                    payloadStandardFile[2] = accessRightsRwCar;
                    payloadStandardFile[3] = accessRightsRW;
                    System.arraycopy(fileSize, 0, payloadStandardFile, 4, 3);
                    writeToUiAppend(readResult, printData("payloadStandardFile", payloadStandardFile));
                    boolean dfCreateStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(readResult, "dfCreateStandardFileResult: " + dfCreateStandardFile);

                    // auth
                    boolean dfAuth1 = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthReadResult: " + dfAuth1);

                    // byte[] payloadWriteData;
                    byte[] dataByte = "22222222".getBytes(StandardCharsets.UTF_8); // 5 bytes long
                    byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning
                    byte lengthOfData = (byte) (dataByte.length & 0xFF);
                    byte[] payloadWriteData = new byte[7 + dataByte.length]; // 7 + length of data
                    payloadWriteData[0] = (byte) desFileNumberStandard; // fileNumber
                    System.arraycopy(offset, 0, payloadWriteData, 1, 3);
                    payloadWriteData[4] = lengthOfData;
                    //payloadStandardFile[5] = 0; // is 0x00
                    //payloadStandardFile[6] = 0; // is 0x00
                    System.arraycopy(dataByte, 0, payloadWriteData, 7, dataByte.length);
                    writeToUiAppend(readResult, printData("payloadWriteData", payloadWriteData));
                    boolean dfWriteStandard = desfire.writeData(payloadWriteData);
                    writeToUiAppend(readResult, "dfWriteStandardResult: " + dfWriteStandard);

                    /*
                    // is my own write method
                    responseData = new byte[2];
                    boolean writeStandardFileSuccess = writeToStandardFile(readResult, desFileNumberStandard, "88887777".getBytes(StandardCharsets.UTF_8), responseData);
                    writeToUiAppend(readResult, "writeStandardFile result: " + writeStandardFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                    if (!writeStandardFileSuccess) {
                        writeToUiAppend(readResult, "the writeStandardFile was not successful, aborted");
                        //return;
                    }

                     */
/*
Desfire write 1942: private boolean write(byte[] payload, byte cmd) throws Exception {




working
send APDU length: 21 data: 903d00000f01000000080000383838383737373700
writeStandardFileResponse length: 2 data: 9100
 */

                    // reader part
                    boolean dfSelect = desfire.selectApplication(desAidStandard);
                    writeToUiAppend(readResult, "dfSelectResult: " + dfSelect);

                    boolean dfAuth = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthReadResult: " + dfAuth);
/*
                    // my own read method
                    // read from standard file
                    responseData = new byte[2];
                    byte[] readStandardFile = readFromStandardFile(readResult, desFileNumberStandard, responseData);
                    writeToUiAppend(readResult, printData("readStandardFile", readStandardFile) + " with response: " + Utils.bytesToHex(responseData));
                    if (!checkResponse(responseData)) {
                        writeToUiAppend(readResult, "the readStandardFile was not successful, aborted");
                    } else {
                        writeToUiAppend(readResult, "readStandardFileResponse: " + new String(readStandardFile, StandardCharsets.UTF_8));
                    }
*/
/*
read in Desfire line 1860 private byte[] read(byte fileNumber, int offset, int length, int cmd) throws Exception {


working own:
send APDU length: 13 data: 90bd 000007 01 000000 200000 00

readStandardFileResponse length: 34 data: 38383838373737370000000000000000000000000000000000000000000000009100
readStandardFile length: 32 data: 3838383837373737000000000000000000000000000000000000000000000000 with response: 9100
readStandardFileResponse: 88887777????????????????????????????????????????????????
 */

                    // get the maximal length from getFileSettings
                    byte[] readStandard = desfire.readData(desFileNumberStandard, (byte) 0x00, (byte) 0x20);
                    writeToUiAppend(readResult, printData("readStandard", readStandard));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readStandard, StandardCharsets.UTF_8));
                    }

/*
fs: RecordDesfireFile [recordSize=32, maxRecords=6, currentRecords=0, records=null, fileType=CYCLIC_RECORD_FILE,
communicationSettings=ENCIPHERED, readAccessKey=0, writeAccessKey=0, readWriteAccessKey=0, changeAccessKey=0, id=2]
 */

                    /*
                    writeToUiAppend(readResult, "kno: " + desfire.getKno());

                    // build payload for Cyclic Record
                    byte[] offsetZero = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
                    String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
                    int contentLengthInt = contentString.length();
                    // todo be more universal with this. The created record size is 32 so this data is fitting into one record
                    byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
                    byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
                    byte[] writeFileParameters = new byte[(contentLengthInt + 7)];
                    writeFileParameters[0] = aesFileNumberCycle;
                    System.arraycopy(offsetZero, 0, writeFileParameters, 1, 3);
                    System.arraycopy(contentLength, 0, writeFileParameters, 4, 3);
                    System.arraycopy(content, 0, writeFileParameters, 7, contentLengthInt);
                    writeToUiAppend(readResult, printData("writeCycleFileParameters DesfireEV1", writeFileParameters));

                    boolean dfWrite = desfire.writeRecord(writeFileParameters);
                    writeToUiAppend(readResult, "dfWrite: " + dfWrite);
                    */

                    // to create a Cyclic file we auth first
                    boolean dfAuthCyclic1 = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthCyclic1Result: " + dfAuthCyclic1);

                    byte[] payloadCyclicFile = new byte[10]; // just to show the length
                    int cyclicFileRecordSize = 32; // 32 bytes
                    int cyclicFileMaxNumberOfRecords = 6; // 5 + 1 spare for writing
                    payloadCyclicFile[0] = desFileNumberCyclic; // fileNumber
                    payloadCyclicFile[1] = communicationSettings;
                    payloadCyclicFile[2] = accessRightsRwCar;
                    payloadCyclicFile[3] = accessRightsRW;
                    System.arraycopy(Utils.intTo3ByteArrayInversed(cyclicFileRecordSize), 0, payloadCyclicFile, 4, 3);
                    System.arraycopy(Utils.intTo3ByteArrayInversed(cyclicFileMaxNumberOfRecords), 0, payloadCyclicFile, 7, 3);
                    writeToUiAppend(readResult, printData("payloadCyclicFile", payloadCyclicFile));
                    boolean dfCreateCyclicFile1 = desfire.createCyclicRecordFile(payloadCyclicFile);
                    writeToUiAppend(readResult, "dfCreateCyclicFile1 Result: " + dfCreateCyclicFile1);

                    // write data to the file
                    byte[] offsetZero = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
                    String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
                    int contentLengthInt = contentString.length();
                    // todo be more universal with this. The created record size is 32 so this data is fitting into one record
                    byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
                    byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
                    byte[] payloadWriteCyclicFile = new byte[(contentLengthInt + 7)];
                    payloadWriteCyclicFile[0] = desFileNumberCyclic;
                    System.arraycopy(offsetZero, 0, payloadWriteCyclicFile, 1, 3);
                    System.arraycopy(contentLength, 0, payloadWriteCyclicFile, 4, 3);
                    System.arraycopy(content, 0, payloadWriteCyclicFile, 7, contentLengthInt);
                    writeToUiAppend(readResult, printData("payloadWriteCyclicFile", payloadWriteCyclicFile));
                    boolean dfWriteToCyclicFile1 = desfire.writeRecord(payloadWriteCyclicFile);
                    writeToUiAppend(readResult, "dfWriteToCyclicFile1 Result: " + dfWriteToCyclicFile1);

                    // don't forget to commit each writing to a record file

                    boolean dfCommitCyclicFile1 = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommitCyclicFile1 Result: " + dfCommitCyclicFile1);

                    // do the auth for reading
                    boolean dfAuthCyclic2 = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthCyclic2 Result: " + dfAuthCyclic2);

                    // get the file settings for the new file
                    responseData = new byte[2];
                    byte[] fileSettingsRecord = getFileSettingsRecord(readResult, desFileNumberCyclic, responseData);
                    writeToUiAppend(readResult, printData("fileSettingsRecord", fileSettingsRecord) + " with response: " + Utils.bytesToHex(responseData));
                    if (!checkResponse(fileSettingsRecord)) {
                        writeToUiAppend(readResult, "the fileSettingsRecord was not successful, aborted");
                        return;
                    }
                    byte[] fileSettingsData = Arrays.copyOf(fileSettingsRecord, fileSettingsRecord.length - 2);
                    int recordsInCyclicFile = 0;
                    if (fileSettingsData.length == 13) {
                        FileSettingRecordModel fsrm = new FileSettingRecordModel(desFileNumberCyclic, fileSettingsData);
                        writeToUiAppend(readResult, fsrm.dumpFileSizes());
                        recordsInCyclicFile = fsrm.getRecordsExisting();
                    }

                    writeToUiAppend(readResult, "reading number of records: " + recordsInCyclicFile);

/*
                    // get the credentials from file
                    DesfireFile dff = desfire.getFileSettings(desFileNumberCyclic);
                    writeToUiAppend(readResult, "getFileSetting: " + dff.toString());
*/

                    for (int i = 0; i < recordsInCyclicFile; i++) {
                        writeToUiAppend(readResult, "cyclic file record number: " + i);
                        byte[] readCyclicFile = desfire.readRecords(desFileNumberCyclic, i, 1); // means from record 0 to 4, reading 1 record per read
                        writeToUiAppend(readResult, printData("readCyclicFile", readCyclicFile));
                        if (readStandard != null) {
                            writeToUiAppend(readResult, new String(readCyclicFile, StandardCharsets.UTF_8));
                        }
                    }


                } catch (IOException e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                } catch (Exception e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                }
            }
        });

        btn23.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this is the DES version with PayloadBuilder
                // auth with DES keys but unencrypted

                // first we setup a des-key secured application
                byte[] responseData = new byte[2];

                DESFireEV1 desfire = new DESFireEV1();
                //desfire.setAdapter(defaultIsoDepAdapter);
                desfire.setAdapter(desFireAdapter);
                PayloadBuilder pb = new PayloadBuilder();
                try {

                    byte[] DES_AID = Utils.hexStringToByteArray("111210");
                    byte applicationMasterKeySettings = (byte) 0x0f; // amks
                    byte[] desKey = new byte[8];
                    byte desKeyNumberRW = (byte) 0;
                    int desFileNumberStandard = 1;
                    int desFileNumberStandard32 = 11;
                    int desFileNumberStandardSize = 32;
                    int desFileNumberValue = 2;
                    int desFileNumberLinear = 3;
                    int desFileLinearSize = 32;
                    int desFileLinearRecords = 5;
                    int desFileNumberCyclic = 4;
                    int desFileCyclicSize = 32;
                    int desFileCyclicRecords = 5;


                    // complete reading
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(readResult, "dfSelectM result: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(desKey, (byte) 0, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthMRead result: " + dfAuthM);

                    // Standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Create application");

                    boolean dfCreateApplication = desfire.createApplication(DES_AID, applicationMasterKeySettings, KeyType.DES, (byte) 3);
                    writeToUiAppend(readResult, "dfCreateApplication result: " + dfCreateApplication);

                    boolean dfSelectApplication = desfire.selectApplication(DES_AID);
                    writeToUiAppend(readResult, "dfSelectApplication result: " + dfSelectApplication);

                    boolean dfAuthApplication = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthApplication result: " + dfAuthApplication);

                    // Standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Standard file");

                    byte[] payloadStandardFile = pb.createStandardFile(desFileNumberStandard, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileNumberStandardSize);
                    boolean dfCreateStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(readResult, "dfCreateStandardFile result: " + dfCreateStandardFile);

                    writeToUiAppend(readResult, "create a Standard file with full 32 bte content");
                    payloadStandardFile = pb.createStandardFile(desFileNumberStandard32, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileNumberStandardSize);
                    dfCreateStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(readResult, "dfCreateStandardFile result: " + dfCreateStandardFile);

                    // auth for writing
                    boolean dfAuthS1 = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthS1 result: " + dfAuthS1);

                    byte[] payloadWriteStandardData = pb.writeToStandardFile(desFileNumberStandard, "*** Standard file data ***");
                    boolean dfWriteStandard = desfire.writeData(payloadWriteStandardData);
                    writeToUiAppend(readResult, "dfWriteStandard result: " + dfWriteStandard);

                    // write a full 32 bytes data
                    writeToUiAppend(readResult, "write Standard file with full 32 bytes content");
                    String data32String = "12345678901234567890123456789012";
                    payloadWriteStandardData = pb.writeToStandardFile(desFileNumberStandard32, data32String);
                    dfWriteStandard = desfire.writeData(payloadWriteStandardData);
                    writeToUiAppend(readResult, "dfWriteStandard result: " + dfWriteStandard);

                    // auth for reading skipped

                    byte[] readStandard = desfire.readData((byte) (desFileNumberStandard & 0xff), (byte) 0x00, (byte) (desFileNumberStandardSize & 0xff));
                    writeToUiAppend(readResult, printData("readStandard", readStandard));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readStandard, StandardCharsets.UTF_8));
                    } else {
                        writeToUiAppend(readResult, "no data available");
                    }

                    writeToUiAppend(readResult, "read Standard file with full 32 bytes content");
                    readStandard = desfire.readData((byte) (desFileNumberStandard32 & 0xff), (byte) 0x00, (byte) (desFileNumberStandardSize & 0xff));
                    writeToUiAppend(readResult, printData("readStandard", readStandard));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readStandard, StandardCharsets.UTF_8));
                    } else {
                        writeToUiAppend(readResult, "no data available");
                    }

                    // value file
                    // linear records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Value file");

                    byte[] payloadValueFile = pb.createValueFile(desFileNumberValue, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0,
                            0, 100, 49);
                    boolean dfCreateValueFile = desfire.createValueFile(payloadValueFile);
                    writeToUiAppend(readResult, "dfCreateValueFile result: " + dfCreateValueFile);

                    // read the value
                    int readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // credit by 11
                    //byte[] payloadCreditData = pb.creditValueFile(desFileNumberValue, 11);
                    boolean dfCreditValue = desfire.credit((byte) (desFileNumberValue & 0xff), 11);
                    writeToUiAppend(readResult, "dfCreditValue result: " + dfCreditValue);

                    // don't forget to commit
                    boolean dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    // read the value
                    readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // debit by 7
                    //byte[] payloadDebitData = pb.debitValueFile(desFileNumberValue, 7);
                    boolean dfDebitValue = desfire.debit((byte) (desFileNumberValue & 0xff), 7);
                    writeToUiAppend(readResult, "dfDebitValue result: " + dfDebitValue);

                    // don't forget to commit
                    dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    // read the value
                    readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // linear records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Linear Records file");

                    byte[] payloadLinearRecordsFile = pb.createLinearRecordsFile(desFileNumberLinear, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileLinearSize, desFileLinearRecords);
                    writeToUiAppend(readResult, printData("payloadLinearRecordsFile", payloadLinearRecordsFile));
                    boolean dfCreateLinearRecordsFile = desfire.createLinearRecordFile(payloadLinearRecordsFile);
                    writeToUiAppend(readResult, "dfCreateLinearRecordsFile result: " + dfCreateLinearRecordsFile);

                    // auth for writing
                    boolean dfAuthL1 = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthL1 result: " + dfAuthL1);

                    try {

                        byte[] payloadWriteLinearData = pb.writeToLinearRecordsFile(desFileNumberLinear, "Entry from " + Utils.getTimestamp());
                        boolean dfWriteLinear = desfire.writeRecord(payloadWriteLinearData);
                        writeToUiAppend(readResult, "dfWriteLinear result: " + dfWriteLinear);

                        // don't forget to commit
                        dfCommit = desfire.commitTransaction();
                        writeToUiAppend(readResult, "dfCommit result: " + dfCommit);
                    } catch (Exception e) {
                        writeToUiAppend(readResult, "We received an error during writing the data to the Linear Records file");
                        writeToUiAppend(readResult, "maybe the file is full; consider to clear the files");
                        writeToUiAppend(readResult, e.getMessage());
                    }
/*
                    for (int i = 0; i < desFileLinearRecords; i++) {
                        writeToUiAppend(readResult, "linear records file record number: " + i);
                        byte[] readLinearRecordsFile = desfire.readRecords((byte) (desFileNumberLinear & 0xff), i, 1); // means from record 0 to 4, reading 1 record per read
                        writeToUiAppend(readResult, printData("readLinearRecordsFile", readLinearRecordsFile));
                        if (readStandard != null) {
                            writeToUiAppend(readResult, new String(readLinearRecordsFile, StandardCharsets.UTF_8));
                        }
                    }
*/
                    // read complete content
                    byte[] readLinearRecordsFile = desfire.readRecords((byte) (desFileNumberLinear & 0xff), 0, 0); // means from record 0 to 4, reading 1 record per read
                    writeToUiAppend(readResult, printData("readLinearRecordsFile", readLinearRecordsFile));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readLinearRecordsFile, StandardCharsets.UTF_8));
                    }

                    // Cyclic Records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Cyclic Records file");

                    byte[] payloadCyclicRecordsFile = pb.createCyclicRecordsFile(desFileNumberCyclic, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileCyclicSize, desFileCyclicRecords);
                    writeToUiAppend(readResult, printData("payloadCyclicRecordsFile", payloadCyclicRecordsFile));
                    boolean dfCreateCyclicRecordsFile = desfire.createCyclicRecordFile(payloadCyclicRecordsFile);
                    writeToUiAppend(readResult, "dfCreateCyclicRecordsFile result: " + dfCreateCyclicRecordsFile);

                    // auth for writing
                    boolean dfAuthC1 = desfire.authenticate(desKey, desKeyNumberRW, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthC1 result: " + dfAuthC1);

                    String dataString = "EntryX from " + Utils.getTimestamp();
                    byte[] payloadWriteCyclicData = pb.writeToCyclicRecordsFile(desFileNumberCyclic, dataString);
                    writeToUiAppend(readResult, "dataString length: " + dataString.length() + " data: " + dataString);
                    boolean dfWriteCyclic = desfire.writeRecord(payloadWriteCyclicData);
                    writeToUiAppend(readResult, "dfWriteCyclic result: " + dfWriteCyclic);

                    // don't forget to commit
                    dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    /*
                    for (int i = 0; i < desFileCyclicRecords; i++) {
                        writeToUiAppend(readResult, "cyclic records file record number: " + i);
                        byte[] readCyclicRecordsFile = desfire.readRecords((byte) (desFileNumberCyclic & 0xff), i, 1); // means from record 0 to 4, reading 1 record per read
                        writeToUiAppend(readResult, printData("readCyclicRecordsFile", readCyclicRecordsFile));
                        if (readStandard != null) {
                            writeToUiAppend(readResult, new String(readCyclicRecordsFile, StandardCharsets.UTF_8));
                        }
                    }
                     */

                    // read complete content
                    byte[] readCyclicRecordsFile = desfire.readRecords((byte) (desFileNumberCyclic & 0xff), 0, 0); // means complete content
                    writeToUiAppend(readResult, printData("readCyclicRecordsFile", readCyclicRecordsFile));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readCyclicRecordsFile, StandardCharsets.UTF_8));
                    }

                } catch (IOException e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                } catch (Exception e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                }
                }
        });

        btn24.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this is the AES version with PayloadBuilder
                // auth with AES keys but unencrypted

                // first we setup a des-key secured application
                byte[] responseData = new byte[2];

                DESFireEV1 desfire = new DESFireEV1();
                //desfire.setAdapter(defaultIsoDepAdapter);
                desfire.setAdapter(desFireAdapter);
                PayloadBuilder pb = new PayloadBuilder();
                try {

                    byte[] AES_AID = Utils.hexStringToByteArray("212220");
                    byte applicationMasterKeySettings = (byte) 0x0f; // amks
                    byte[] desKey = new byte[8]; // for the master application
                    byte[] aesKey = new byte[16];
                    byte desKeyNumberRW = (byte) 0;
                    int desFileNumberStandard = 1;
                    int desFileNumberStandard32 = 11;
                    int desFileNumberStandardSize = 32;
                    int desFileNumberValue = 2;
                    int desFileNumberLinear = 3;
                    int desFileLinearSize = 32;
                    int desFileLinearRecords = 5;
                    int desFileNumberCyclic = 4;
                    int desFileCyclicSize = 32;
                    int desFileCyclicRecords = 5;

                    // complete reading
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(readResult, "dfSelectM result: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(desKey, (byte) 0, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthMRead result: " + dfAuthM);

                    // Standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Create application");

                    boolean dfCreateApplication = desfire.createApplication(AES_AID, applicationMasterKeySettings, KeyType.AES, (byte) 3);
                    writeToUiAppend(readResult, "dfCreateApplication result: " + dfCreateApplication);

                    boolean dfSelectApplication = desfire.selectApplication(AES_AID);
                    writeToUiAppend(readResult, "dfSelectApplication result: " + dfSelectApplication);

                    boolean dfAuthApplication = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthApplication result: " + dfAuthApplication);

                    // Standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Standard file");

                    byte[] payloadStandardFile = pb.createStandardFile(desFileNumberStandard, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileNumberStandardSize);
                    boolean dfCreateStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(readResult, "dfCreateStandardFile result: " + dfCreateStandardFile);

                    writeToUiAppend(readResult, "create a Standard file with full 32 bte content");
                    payloadStandardFile = pb.createStandardFile(desFileNumberStandard32, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileNumberStandardSize);
                    dfCreateStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(readResult, "dfCreateStandardFile result: " + dfCreateStandardFile);

                    // auth for writing
                    boolean dfAuthS1 = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthS1 result: " + dfAuthS1);

                    byte[] payloadWriteStandardData = pb.writeToStandardFile(desFileNumberStandard, "*** Standard file data ***");
                    boolean dfWriteStandard = desfire.writeData(payloadWriteStandardData);
                    writeToUiAppend(readResult, "dfWriteStandard result: " + dfWriteStandard);

                    // write a full 32 bytes data
                    writeToUiAppend(readResult, "write Standard file with full 32 bytes content");
                    String data32String = "12345678901234567890123456789012";
                    payloadWriteStandardData = pb.writeToStandardFile(desFileNumberStandard32, data32String);
                    dfWriteStandard = desfire.writeData(payloadWriteStandardData);
                    writeToUiAppend(readResult, "dfWriteStandard result: " + dfWriteStandard);

                    // auth for reading skipped

                    byte[] readStandard = desfire.readData((byte) (desFileNumberStandard & 0xff), (byte) 0x00, (byte) (desFileNumberStandardSize & 0xff));
                    writeToUiAppend(readResult, printData("readStandard", readStandard));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readStandard, StandardCharsets.UTF_8));
                    } else {
                        writeToUiAppend(readResult, "no data available");
                    }

                    writeToUiAppend(readResult, "read Standard file with full 32 bytes content");
                    readStandard = desfire.readData((byte) (desFileNumberStandard32 & 0xff), (byte) 0x00, (byte) (desFileNumberStandardSize & 0xff));
                    writeToUiAppend(readResult, printData("readStandard", readStandard));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readStandard, StandardCharsets.UTF_8));
                    } else {
                        writeToUiAppend(readResult, "no data available");
                    }

                    // value file
                    // linear records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Value file");

                    byte[] payloadValueFile = pb.createValueFile(desFileNumberValue, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0,
                            0, 100, 49);
                    boolean dfCreateValueFile = desfire.createValueFile(payloadValueFile);
                    writeToUiAppend(readResult, "dfCreateValueFile result: " + dfCreateValueFile);

                    // read the value
                    int readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // credit by 11
                    //byte[] payloadCreditData = pb.creditValueFile(desFileNumberValue, 11);
                    boolean dfCreditValue = desfire.credit((byte) (desFileNumberValue & 0xff), 11);
                    writeToUiAppend(readResult, "dfCreditValue result: " + dfCreditValue);

                    // don't forget to commit
                    boolean dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    // read the value
                    readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // debit by 7
                    //byte[] payloadDebitData = pb.debitValueFile(desFileNumberValue, 7);
                    boolean dfDebitValue = desfire.debit((byte) (desFileNumberValue & 0xff), 7);
                    writeToUiAppend(readResult, "dfDebitValue result: " + dfDebitValue);

                    // don't forget to commit
                    dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    // read the value
                    readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // linear records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Linear Records file");

                    byte[] payloadLinearRecordsFile = pb.createLinearRecordsFile(desFileNumberLinear, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileLinearSize, desFileLinearRecords);
                    writeToUiAppend(readResult, printData("payloadLinearRecordsFile", payloadLinearRecordsFile));
                    boolean dfCreateLinearRecordsFile = desfire.createLinearRecordFile(payloadLinearRecordsFile);
                    writeToUiAppend(readResult, "dfCreateLinearRecordsFile result: " + dfCreateLinearRecordsFile);

                    // auth for writing
                    boolean dfAuthL1 = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthL1 result: " + dfAuthL1);

                    try {

                        byte[] payloadWriteLinearData = pb.writeToLinearRecordsFile(desFileNumberLinear, "Entry from " + Utils.getTimestamp());
                        boolean dfWriteLinear = desfire.writeRecord(payloadWriteLinearData);
                        writeToUiAppend(readResult, "dfWriteLinear result: " + dfWriteLinear);

                        // don't forget to commit
                        dfCommit = desfire.commitTransaction();
                        writeToUiAppend(readResult, "dfCommit result: " + dfCommit);
                    } catch (Exception e) {
                        writeToUiAppend(readResult, "We received an error during writing the data to the Linear Records file");
                        writeToUiAppend(readResult, "maybe the file is full; consider to clear the files");
                        writeToUiAppend(readResult, e.getMessage());
                    }
/*
                    for (int i = 0; i < desFileLinearRecords; i++) {
                        writeToUiAppend(readResult, "linear records file record number: " + i);
                        byte[] readLinearRecordsFile = desfire.readRecords((byte) (desFileNumberLinear & 0xff), i, 1); // means from record 0 to 4, reading 1 record per read
                        writeToUiAppend(readResult, printData("readLinearRecordsFile", readLinearRecordsFile));
                        if (readStandard != null) {
                            writeToUiAppend(readResult, new String(readLinearRecordsFile, StandardCharsets.UTF_8));
                        }
                    }
*/
                    // read complete content
                    byte[] readLinearRecordsFile = desfire.readRecords((byte) (desFileNumberLinear & 0xff), 0, 0); // means from record 0 to 4, reading 1 record per read
                    writeToUiAppend(readResult, printData("readLinearRecordsFile", readLinearRecordsFile));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readLinearRecordsFile, StandardCharsets.UTF_8));
                    }

                    // Cyclic Records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Cyclic Records file");

                    byte[] payloadCyclicRecordsFile = pb.createCyclicRecordsFile(desFileNumberCyclic, PayloadBuilder.CommunicationSetting.Plain,
                            0, 0, 0, 0, desFileCyclicSize, desFileCyclicRecords);
                    writeToUiAppend(readResult, printData("payloadCyclicRecordsFile", payloadCyclicRecordsFile));
                    boolean dfCreateCyclicRecordsFile = desfire.createCyclicRecordFile(payloadCyclicRecordsFile);
                    writeToUiAppend(readResult, "dfCreateCyclicRecordsFile result: " + dfCreateCyclicRecordsFile);

                    // auth for writing
                    boolean dfAuthC1 = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthC1 result: " + dfAuthC1);

                    String dataString = "EntryX from " + Utils.getTimestamp();
                    byte[] payloadWriteCyclicData = pb.writeToCyclicRecordsFile(desFileNumberCyclic, dataString);
                    writeToUiAppend(readResult, "dataString length: " + dataString.length() + " data: " + dataString);
                    boolean dfWriteCyclic = desfire.writeRecord(payloadWriteCyclicData);
                    writeToUiAppend(readResult, "dfWriteCyclic result: " + dfWriteCyclic);

                    // don't forget to commit
                    dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    /*
                    for (int i = 0; i < desFileCyclicRecords; i++) {
                        writeToUiAppend(readResult, "cyclic records file record number: " + i);
                        byte[] readCyclicRecordsFile = desfire.readRecords((byte) (desFileNumberCyclic & 0xff), i, 1); // means from record 0 to 4, reading 1 record per read
                        writeToUiAppend(readResult, printData("readCyclicRecordsFile", readCyclicRecordsFile));
                        if (readStandard != null) {
                            writeToUiAppend(readResult, new String(readCyclicRecordsFile, StandardCharsets.UTF_8));
                        }
                    }
                     */

                    // read complete content
                    byte[] readCyclicRecordsFile = desfire.readRecords((byte) (desFileNumberCyclic & 0xff), 0, 0); // means complete content
                    writeToUiAppend(readResult, printData("readCyclicRecordsFile", readCyclicRecordsFile));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readCyclicRecordsFile, StandardCharsets.UTF_8));
                    }

                } catch (IOException e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                } catch (Exception e) {
                    writeToUiAppend(readResult, "Error with DESFireEV1 + " + e.getMessage());
                }
            }
        });

        btn25.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this is the AES version with PayloadBuilder
                // auth with AES keys AND encrypted

                // first we setup a des-key secured application
                byte[] responseData = new byte[2];

                DESFireEV1 desfire = new DESFireEV1();
                //desfire.setAdapter(defaultIsoDepAdapter);
                desfire.setAdapter(desFireAdapter);
                PayloadBuilder pb = new PayloadBuilder();
                try {

                    byte[] AES_AID = Utils.hexStringToByteArray("414240");
                    byte applicationMasterKeySettings = (byte) 0x0f; // amks
                    byte[] desKey = new byte[8]; // for the master application
                    byte[] aesKey = new byte[16];
                    byte desKeyNumberRW = (byte) 0;
                    int desFileNumberStandard = 1;
                    int desFileNumberStandard32 = 11;
                    int desFileNumberStandardSize = 32;
                    int desFileNumberValue = 2;
                    int desFileNumberLinear = 3;
                    int desFileLinearSize = 32;
                    int desFileLinearRecords = 5;
                    int desFileNumberCyclic = 4;
                    int desFileCyclicSize = 32;
                    int desFileCyclicRecords = 5;

                    // complete reading
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(readResult, "dfSelectM result: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(desKey, (byte) 0, KeyType.DES);
                    writeToUiAppend(readResult, "dfAuthMRead result: " + dfAuthM);

                    // Standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Create application");

                    boolean dfCreateApplication = desfire.createApplication(AES_AID, applicationMasterKeySettings, KeyType.AES, (byte) 3);
                    writeToUiAppend(readResult, "dfCreateApplication result: " + dfCreateApplication);

                    boolean dfSelectApplication = desfire.selectApplication(AES_AID);
                    writeToUiAppend(readResult, "dfSelectApplication result: " + dfSelectApplication);

                    boolean dfAuthApplication = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthApplication result: " + dfAuthApplication);

                    // Standard file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Standard file");

                    byte[] payloadStandardFile = pb.createStandardFile(desFileNumberStandard, PayloadBuilder.CommunicationSetting.Encrypted,
                            0, 0, 0, 0, desFileNumberStandardSize);
                    boolean dfCreateStandardFile = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(readResult, "dfCreateStandardFile result: " + dfCreateStandardFile);
/*
MACed seems not to work
                    writeToUiAppend(readResult, "create a Standard file with full 32 bte content");
                    byte[]  payloadStandardFile32 = pb.createStandardFile(desFileNumberStandard32, PayloadBuilder.CommunicationSetting.MACed,
                            0, 0, 0, 0, desFileNumberStandardSize);
                    boolean dfCreateStandardFile32 = desfire.createStdDataFile(payloadStandardFile32);
                    writeToUiAppend(readResult, "dfCreateStandardFile32 result: " + dfCreateStandardFile32);
*/

                    // auth for writing
                    boolean dfAuthS1 = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthS1 result: " + dfAuthS1);

                    String dataStandardString = "*** Standard file data ***";
                    String dataStandard24String =  "abcdefghijklmnopqrstuvwx";
                    String dataStandard24String2 = "123456789012345678901234";
                    //String dataStandard32String = "12345678901234567890123456789012";
                    byte[] payloadWriteStandardData = pb.writeToStandardFile(desFileNumberStandard, dataStandard24String);
                    boolean dfWriteStandard = desfire.writeData(payloadWriteStandardData);
                    writeToUiAppend(readResult, "dfWriteStandard result: " + dfWriteStandard);
/*
                    // write a full 32 bytes data
                    writeToUiAppend(readResult, "write Standard file with full 32 bytes content");
                    String data32String = "12345678901234567890123456789012";
                    payloadWriteStandardData = pb.writeToStandardFile(desFileNumberStandard32, data32String);
                    dfWriteStandard = desfire.writeData(payloadWriteStandardData);
                    writeToUiAppend(readResult, "dfWriteStandard result: " + dfWriteStandard);
*/
                    // auth for reading skipped

                    byte[] readStandard = desfire.readData((byte) (desFileNumberStandard & 0xff), (byte) 0x00, (byte) (desFileNumberStandardSize & 0xff));
                    writeToUiAppend(readResult, printData("readStandard", readStandard));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readStandard, StandardCharsets.UTF_8));
                    } else {
                        writeToUiAppend(readResult, "no data available");
                    }

/*
Actual app status:
In DESFireEV1 some read & write methods have hardcoded ENCIPHERED flags instead of Plain/MACed or ENCIPHERED
second: the calculated CMAC does not match the expected one
but now I can work on reading the AES encrypted file


 */



/*
                    writeToUiAppend(readResult, "read Standard file with full 32 bytes content");
                    readStandard = desfire.readData((byte) (desFileNumberStandard32 & 0xff), (byte) 0x00, (byte) (desFileNumberStandardSize & 0xff));
                    writeToUiAppend(readResult, printData("readStandard", readStandard));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readStandard, StandardCharsets.UTF_8));
                    } else {
                        writeToUiAppend(readResult, "no data available");
                    }
*/
/*
                    // value file
                    // linear records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Value file");

                    byte[] payloadValueFile = pb.createValueFile(desFileNumberValue, PayloadBuilder.CommunicationSetting.Encrypted,
                            0, 0, 0, 0,
                            0, 100, 49);
                    boolean dfCreateValueFile = desfire.createValueFile(payloadValueFile);
                    writeToUiAppend(readResult, "dfCreateValueFile result: " + dfCreateValueFile);

                    // read the value
                    int readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // credit by 11
                    //byte[] payloadCreditData = pb.creditValueFile(desFileNumberValue, 11);
                    boolean dfCreditValue = desfire.credit((byte) (desFileNumberValue & 0xff), 11);
                    writeToUiAppend(readResult, "dfCreditValue result: " + dfCreditValue);

                    // don't forget to commit
                    boolean dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    // read the value
                    readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // debit by 7
                    //byte[] payloadDebitData = pb.debitValueFile(desFileNumberValue, 7);
                    boolean dfDebitValue = desfire.debit((byte) (desFileNumberValue & 0xff), 7);
                    writeToUiAppend(readResult, "dfDebitValue result: " + dfDebitValue);

                    // don't forget to commit
                    dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);

                    // read the value
                    readValue = desfire.getValue((byte) (desFileNumberValue & 0xff));
                    writeToUiAppend(readResult, "getValue: " + readValue);

                    // linear records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Linear Records file");

                    byte[] payloadLinearRecordsFile = pb.createLinearRecordsFile(desFileNumberLinear, PayloadBuilder.CommunicationSetting.Encrypted,
                            0, 0, 0, 0, desFileLinearSize, desFileLinearRecords);
                    writeToUiAppend(readResult, printData("payloadLinearRecordsFile", payloadLinearRecordsFile));
                    boolean dfCreateLinearRecordsFile = desfire.createLinearRecordFile(payloadLinearRecordsFile);
                    writeToUiAppend(readResult, "dfCreateLinearRecordsFile result: " + dfCreateLinearRecordsFile);

                    // auth for writing
                    boolean dfAuthL1 = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthL1 result: " + dfAuthL1);

                    try {

                        byte[] payloadWriteLinearData = pb.writeToLinearRecordsFile(desFileNumberLinear, "Entry from " + Utils.getTimestamp());
                        boolean dfWriteLinear = desfire.writeRecord(payloadWriteLinearData);
                        writeToUiAppend(readResult, "dfWriteLinear result: " + dfWriteLinear);

                        // don't forget to commit
                        dfCommit = desfire.commitTransaction();
                        writeToUiAppend(readResult, "dfCommit result: " + dfCommit);
                    } catch (Exception e) {
                        writeToUiAppend(readResult, "We received an error during writing the data to the Linear Records file");
                        writeToUiAppend(readResult, "maybe the file is full; consider to clear the files");
                        writeToUiAppend(readResult, e.getMessage());
                    }

 */
/*
                    for (int i = 0; i < desFileLinearRecords; i++) {
                        writeToUiAppend(readResult, "linear records file record number: " + i);
                        byte[] readLinearRecordsFile = desfire.readRecords((byte) (desFileNumberLinear & 0xff), i, 1); // means from record 0 to 4, reading 1 record per read
                        writeToUiAppend(readResult, printData("readLinearRecordsFile", readLinearRecordsFile));
                        if (readStandard != null) {
                            writeToUiAppend(readResult, new String(readLinearRecordsFile, StandardCharsets.UTF_8));
                        }
                    }
*/
                    /*
                    // read complete content
                    byte[] readLinearRecordsFile = desfire.readRecords((byte) (desFileNumberLinear & 0xff), 0, 0); // means from record 0 to 4, reading 1 record per read
                    writeToUiAppend(readResult, printData("readLinearRecordsFile", readLinearRecordsFile));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readLinearRecordsFile, StandardCharsets.UTF_8));
                    }

                    // Cyclic Records file
                    writeToUiAppend(readResult, "");
                    writeToUiAppend(readResult, "Cyclic Records file");

                    byte[] payloadCyclicRecordsFile = pb.createCyclicRecordsFile(desFileNumberCyclic, PayloadBuilder.CommunicationSetting.Encrypted,
                            0, 0, 0, 0, desFileCyclicSize, desFileCyclicRecords);
                    writeToUiAppend(readResult, printData("payloadCyclicRecordsFile", payloadCyclicRecordsFile));
                    boolean dfCreateCyclicRecordsFile = desfire.createCyclicRecordFile(payloadCyclicRecordsFile);
                    writeToUiAppend(readResult, "dfCreateCyclicRecordsFile result: " + dfCreateCyclicRecordsFile);

                    // auth for writing
                    boolean dfAuthC1 = desfire.authenticate(aesKey, desKeyNumberRW, KeyType.AES);
                    writeToUiAppend(readResult, "dfAuthC1 result: " + dfAuthC1);

                    String dataString = "EntryX from " + Utils.getTimestamp();
                    byte[] payloadWriteCyclicData = pb.writeToCyclicRecordsFile(desFileNumberCyclic, dataString);
                    writeToUiAppend(readResult, "dataString length: " + dataString.length() + " data: " + dataString);
                    boolean dfWriteCyclic = desfire.writeRecord(payloadWriteCyclicData);
                    writeToUiAppend(readResult, "dfWriteCyclic result: " + dfWriteCyclic);

                    // don't forget to commit
                    dfCommit = desfire.commitTransaction();
                    writeToUiAppend(readResult, "dfCommit result: " + dfCommit);
*/
                    /*
                    for (int i = 0; i < desFileCyclicRecords; i++) {
                        writeToUiAppend(readResult, "cyclic records file record number: " + i);
                        byte[] readCyclicRecordsFile = desfire.readRecords((byte) (desFileNumberCyclic & 0xff), i, 1); // means from record 0 to 4, reading 1 record per read
                        writeToUiAppend(readResult, printData("readCyclicRecordsFile", readCyclicRecordsFile));
                        if (readStandard != null) {
                            writeToUiAppend(readResult, new String(readCyclicRecordsFile, StandardCharsets.UTF_8));
                        }
                    }
                     */
/*
                    // read complete content
                    byte[] readCyclicRecordsFile = desfire.readRecords((byte) (desFileNumberCyclic & 0xff), 0, 0); // means complete content
                    writeToUiAppend(readResult, printData("readCyclicRecordsFile", readCyclicRecordsFile));
                    if (readStandard != null) {
                        writeToUiAppend(readResult, new String(readCyclicRecordsFile, StandardCharsets.UTF_8));
                    }
*/
                } catch (IOException e) {
                    writeToUiAppend(readResult, "IOEx Error with DESFireEV1 + " + e.getMessage());
                } catch (Exception e) {
                    writeToUiAppend(readResult, "Ex Error with DESFireEV1 + " + e.getMessage());
                }
            }
        });

        btn26.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // try to decrypt an AES encrypted Standard File

                byte[] AES_AID = Utils.hexStringToByteArray("414240");
                byte applicationMasterKeySettings = (byte) 0x0f; // amks
                byte[] desKey = new byte[8]; // for the master application
                byte desKeyNumber0 = (byte) 0; // for the master application
                byte[] aesKey = new byte[16];
                byte aesKeyNumberRW = (byte) 0;
                int aesFileNumberStandard = 1;
                int aesFileNumberStandardSize = 32;


                // select the master file application
                byte[] responseData = new byte[2];
                boolean selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectMasterApplication result: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, desKeyNumber0, desKey, false, responseData);
                writeToUiAppend(readResult, "authenticateMasterApplication result: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the authenticationMaster was not successful, aborted");
                    return;
                }

                // select the application
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AES_AID, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                // authenticate wit aes key 0
                responseData = new byte[2];
                boolean authenticateReadSuccess = authenticateApplicationAes(readResult, aesKeyNumberRW, aesKey, true, responseData);
                writeToUiAppend(readResult, "authenticateRead result: " + authenticateReadSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateReadSuccess) {
                    writeToUiAppend(readResult, "the authenticationRead was not successful, aborted");
                    return;
                }

                // we do need the Cryp unit
                Cryp cryp = new Cryp(skeyOwn, ivOwn);

                // read the standard file
                responseData = new byte[2];
                // we need to know how long this Standard File is
                byte[] readEncryptedData = readFromStandardFileAes(readResult, (byte) (aesFileNumberStandard & 0xff), responseData, cryp, aesFileNumberStandardSize);
                // update the IV
                ivOwn = cryp.getIv();

                writeToUiAppend(readResult, printData("readEncryptedData", readEncryptedData));
                writeToUiAppend(readResult, printData("responseData", responseData));
                if (readEncryptedData != null) {
                    writeToUiAppend(readResult, new String(readEncryptedData, StandardCharsets.UTF_8));
                } else {
                    writeToUiAppend(readResult, "no data available");
                }

                // working on decryption and CMAC validation using these static data
                byte[] decSessionKey = Utils.hexStringToByteArray("00000000000000000000000000000000");
                byte[] decIv = Utils.hexStringToByteArray("00010203681463f60c0d0e0fc3f96400");
                byte[] decCrypData = Utils.hexStringToByteArray("b2c969b5f64fc6ea5e0cf8cd708f3f774c970aa11e68285d775a2b74167e6348b3dc1d59a109b3cb17c6c3568b65414f9100");
                // send APDU length: 13 data: 90bd0000070100000020000000
                byte[] decReadCommandApdu = Utils.hexStringToByteArray("90bd0000070100000020000000");

            }
        });

        btn27.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // decryption of static data
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "Manual decryption of card data");

                // working on decryption and CMAC validation using these static data
                byte[] decSessionKey = Utils.hexStringToByteArray("00010203681463f60c0d0e0fc3f96400");
                byte[] decIv = Utils.hexStringToByteArray("00000000000000000000000000000000");
                byte[] decCryptedDataStatus = Utils.hexStringToByteArray("b2c969b5f64fc6ea5e0cf8cd708f3f774c970aa11e68285d775a2b74167e6348b3dc1d59a109b3cb17c6c3568b65414f9100");
                byte[] decReadCommandApdu = Utils.hexStringToByteArray("90bd0000070100000020000000"); // 13 byte

                writeToUiAppend(readResult, printData("dec SessionKey", decSessionKey));
                writeToUiAppend(readResult, printData("dec IV        ", decIv));
                writeToUiAppend(readResult, printData("dec Cryp Data ", decCryptedDataStatus));
                writeToUiAppend(readResult, printData("Read Cmd APDU ", decReadCommandApdu));
                byte[] decCryptedData = Arrays.copyOf(decCryptedDataStatus, decCryptedDataStatus.length - 2);
                writeToUiAppend(readResult, printData("dec Cryp Data ", decCryptedData));
                byte[] plaintextCrc = new byte[0];
                byte[] decIvApp = Utils.hexStringToByteArray("8d778afbd8fd4201ce243e017aafc953");
                try {
                    plaintextCrc = decryptAes(decCryptedData, decSessionKey, decIv);
                    //plaintextCrc = decryptAes(decCryptedData, decSessionKey, decIvApp);
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "Error during decryption: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("plainCrc Data ", plaintextCrc));
                if (plaintextCrc != null) {
                    writeToUiAppend(readResult, new String (plaintextCrc, StandardCharsets.UTF_8));
                }

                // that does not work, the first 16 bytes are scrambled due to wrong IV
                // �_�~9�uF`M,jqrstuvwx56789012��&�????????????????????????
                // plainCrc Data  length: 48 data: f80f5fec7e1a391ddd754617604d2c6a71727374757677783536373839303132aad226da000000000000000000000000
                //           | wrap
                //             | cmd
                //                     | file number
                // full APDU 90bd0000070100000020000000
                // readCmd     bd        00000000100000
                // readCmd     bd00000000100000
                //           0 1 2 3 4 5 6 7 8 9 0 1 2
                //
                // so we need bytes 1, 6 - 12
                byte[] commandForCrc = new byte[8];
                commandForCrc[0] = decReadCommandApdu[1];
                System.arraycopy(decReadCommandApdu, 6, commandForCrc, 1, 7);
                writeToUiAppend(readResult, printData("com for CRC", commandForCrc));
                writeToUiAppend(readResult, "com expectd length 08 data: bd00000020000000");
                // data is ok by manual view

                // Desfire line 1884: read
                Cryp cryp = new Cryp(decSessionKey, decIv);
                // preprocess the read command to get a new iv
                writeToUiAppend(readResult, printData("skey before preproc", cryp.getSkey()));
                writeToUiAppend(readResult, printData("IV   before preproc", cryp.getIv()));
                //byte[] apduCommandAfterPreprocessing = cryp.preprocessAes(commandForCrc, 0);
                //byte[] apduCommandAfterPreprocessing = cryp.preprocessPlain(commandForCrc); // the read command is in PLAIN
                byte[] apduCommandAfterPreprocessing = cryp.preprocessPlain(decReadCommandApdu); // the read command is in PLAIN
                // we should have a changed iv
                writeToUiAppend(readResult, printData("com for CRC", apduCommandAfterPreprocessing));
                writeToUiAppend(readResult, printData("skey after  preproc", cryp.getSkey()));
                writeToUiAppend(readResult, printData("IV   after  preproc", cryp.getIv()));

                // decrypt
                byte[] cryptPlaintext1 = cryp.postprocessEnciphered(decCryptedDataStatus, 32); // full received apdu with status
                writeToUiAppend(readResult, printData("cryp Plaintext 1 ", cryptPlaintext1));
                if (cryptPlaintext1 != null) {
                    writeToUiAppend(readResult, new String (cryptPlaintext1, StandardCharsets.UTF_8));
                }
            }
        });

        btn28.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // write AES encrypted to Standard file
                byte[] AES_AID = Utils.hexStringToByteArray("414240");
                byte applicationMasterKeySettings = (byte) 0x0f; // amks
                byte[] desKey = new byte[8]; // for the master application
                byte desKeyNumber0 = (byte) 0; // for the master application
                byte[] aesKey = new byte[16];
                byte aesKeyNumberRW = (byte) 0;
                int aesFileNumberStandard = 3; // this is file no 03 = self written encrypted data
                int aesFileNumberStandardSize = 32;

                // select the master file application
                byte[] responseData = new byte[2];
                boolean selectMasterApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectMasterApplication result: " + selectMasterApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));

                // authenticate
                responseData = new byte[2];
                // we set the rw + car rights to key 0 so we need to authenticate with key 0 first to proceed
                boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, desKeyNumber0, desKey, false, responseData);
                writeToUiAppend(readResult, "authenticateMasterApplication result: " + authenticateMasterSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateMasterSuccess) {
                    writeToUiAppend(readResult, "the authenticationMaster was not successful, aborted");
                    return;
                }

                // select the application
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AES_AID, responseData);
                writeToUiAppend(readResult, "selectApplication result: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!selectApplicationSuccess) {
                    writeToUiAppend(readResult, "the selectApplication was not successful, aborted");
                    return;
                }

                // create the standard file
                responseData = new byte[2];
                boolean createStandardFileSuccess = createStandardFile(readResult, (byte) (aesFileNumberStandard & 0xff), responseData);
                writeToUiAppend(readResult, "createStandardFile result: " + createStandardFileSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!createStandardFileSuccess) {
                    writeToUiAppend(readResult, "the createStandardFile was not successful, aborted");
                    return;
                }

                // authenticate wit aes key 0
                responseData = new byte[2];
                boolean authenticateWriteSuccess = authenticateApplicationAes(readResult, aesKeyNumberRW, aesKey, true, responseData);
                writeToUiAppend(readResult, "authenticateWrite result: " + authenticateWriteSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!authenticateWriteSuccess) {
                    writeToUiAppend(readResult, "the authenticationWrite was not successful, aborted");
                    return;
                }

                // we do need the Cryp unit
                Cryp cryp = new Cryp(skeyOwn, ivOwn);

                // write to the standard file
                responseData = new byte[2];
                // we need to know how long this Standard File is
                //byte[] data = "6655443322".getBytes(StandardCharsets.UTF_8);
                byte[] dataStandard24 =  "abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.UTF_8);
                boolean writeEncryptedDataSuccess = writeToStandardFileAes(readResult, (byte) (aesFileNumberStandard & 0xff), dataStandard24, responseData, cryp);
                writeToUiAppend(readResult, "writeEncryptedData result: " + writeEncryptedDataSuccess + " with response: " + Utils.bytesToHex(responseData));
                if (!writeEncryptedDataSuccess) {
                    writeToUiAppend(readResult, "the writeEncryptedData was not successful, aborted");
                    return;
                }

                // update the IV
                ivOwn = cryp.getIv();

                /*
                writeToUiAppend(readResult, printData("readEncryptedData", readEncryptedData));
                writeToUiAppend(readResult, printData("responseData", responseData));
                if (readEncryptedData != null) {
                    writeToUiAppend(readResult, new String(readEncryptedData, StandardCharsets.UTF_8));
                } else {
                    writeToUiAppend(readResult, "no data available");
                }

                // working on decryption and CMAC validation using these static data
                byte[] decSessionKey = Utils.hexStringToByteArray("00000000000000000000000000000000");
                byte[] decIv = Utils.hexStringToByteArray("00010203681463f60c0d0e0fc3f96400");
                byte[] decCrypData = Utils.hexStringToByteArray("b2c969b5f64fc6ea5e0cf8cd708f3f774c970aa11e68285d775a2b74167e6348b3dc1d59a109b3cb17c6c3568b65414f9100");
                // send APDU length: 13 data: 90bd0000070100000020000000
                byte[] decReadCommandApdu = Utils.hexStringToByteArray("90bd0000070100000020000000");

*/



            }
        });

    }


    /**
     * start section for ready to use commands
     */

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
     * @throws IOException
     * @return true for success
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
            writeToUiAppend(logTextView, "createApplicationDes tranceive failed: " + e.getMessage());
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
            writeToUiAppend(logTextView, "selectApplicationDes tranceive failed: " + e.getMessage());
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
            writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
            return null;
        }
    }

    private List<byte[]> getApplicationIdsList(TextView logTextView, byte[] response) {
        // get application ids
        List<byte[]> applicationIdList = new ArrayList<>();
        byte getApplicationIdsCommand = (byte) 0x6a;
        byte[] getApplicationIdsResponse = new byte[0];
        try {
            getApplicationIdsResponse = isoDep.transceive(wrapMessage(getApplicationIdsCommand, null));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("getApplicationIdsResponse", getApplicationIdsResponse));
        // getApplicationIdsResponse length: 2 data: 9100 = no applications on card
        // getApplicationIdsResponse length: 5 data: a1a2a3 9100
        // there might be more application on the card that fit into one frame:
        // getApplicationIdsResponse length: 5 data: a1a2a3 91AF
        // AF at the end is indicating more data

        // check that result if 0x9100 (success) or 0x91AF (success but more data)
        if ((!checkResponse(getApplicationIdsResponse)) && (!checkResponseMoreData(getApplicationIdsResponse))) {
            // something got wrong (e.g. missing authentication ?)
            writeToUiAppend(logTextView, "there was an unexpected response");
            return null;
        }
        // if the read result is success 9100 we return the data received so far
        if (checkResponse(getApplicationIdsResponse)) {
            System.arraycopy(returnStatusBytes(getApplicationIdsResponse), 0, response, 0, 2);
            byte[] applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
            applicationIdList = divideArray(applicationListBytes, 3);
            return applicationIdList;
        }
        if (checkResponseMoreData(getApplicationIdsResponse)) {
            writeToUiAppend(logTextView, "getApplicationIdsList: we are asked to grab more data from the card");
            byte[] applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
            applicationIdList = divideArray(applicationListBytes, 3);
            byte getMoreDataCommand = (byte) 0xaf;
            boolean readMoreData = true;
            try {
                while (readMoreData) {
                    try {
                        getApplicationIdsResponse = isoDep.transceive(wrapMessage(getMoreDataCommand, null));
                    } catch (Exception e) {
                        //throw new RuntimeException(e);
                        writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
                        return null;
                    }
                    writeToUiAppend(logTextView, printData("getApplicationIdsResponse", getApplicationIdsResponse));
                    if (checkResponse(getApplicationIdsResponse)) {
                        // now we have received all data
                        List<byte[]> applicationIdListTemp = new ArrayList<>();
                        System.arraycopy(returnStatusBytes(getApplicationIdsResponse), 0, response, 0, 2);
                        applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
                        applicationIdListTemp = divideArray(applicationListBytes, 3);
                        readMoreData = false; // end the loop
                        applicationIdList.addAll(applicationIdListTemp);
                        return applicationIdList;
                    }
                    if (checkResponseMoreData(getApplicationIdsResponse)) {
                        // some more data will follow, store temp data
                        List<byte[]> applicationIdListTemp = new ArrayList<>();
                        applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
                        applicationIdListTemp = divideArray(applicationListBytes, 3);
                        applicationIdList.addAll(applicationIdListTemp);
                        readMoreData = true;
                    }
                } // while (readMoreData) {
            } catch (Exception e) {
                writeToUiAppend(logTextView, "Exception failure: " + e.getMessage());
            } // try
        }
        return null;
    }

    private int getFreeMemory(TextView logTextView, byte[] response) {
        // get the free memory on the card
        byte getFreeMemoryCommand = (byte) 0x6e;
        byte[] getFreeMemoryResponse = new byte[0];
        try {
            getFreeMemoryResponse = isoDep.transceive(wrapMessage(getFreeMemoryCommand, null));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return 0;
        }
        writeToUiAppend(logTextView, printData("getFreeMemoryResponse", getFreeMemoryResponse));
        // getFreeMemoryResponse length: 5 data: 400800 9100 (EV1 2K after create 1 app + 1 32 byte file)
        // getFreeMemoryResponse length: 5 data: 000a00 9100 (EV2 2K empty)
        // getFreeMemoryResponse length: 5 data: 001400 9100 (EV2 4K empty)
        // 400800 = 00 08 40 = 2112 bytes
        // 000a00 = 00 0a 00 = 2560 bytes
        // 001400 = 00 14 00 = 5120 bytes
        int memorySize = 0;
        if (getFreeMemoryResponse.length > 2) {
            byte[] lengthBytes = Arrays.copyOf(getFreeMemoryResponse, getFreeMemoryResponse.length - 2);
            memorySize = byteArrayLength3InversedToInt(lengthBytes);
            writeToUiAppend(logTextView, "free memory on card: " + memorySize);
        }
        System.arraycopy(returnStatusBytes(getFreeMemoryResponse), 0, response, 0, 2);
        return memorySize;
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
            writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
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
            writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("readStandardFileResponse", readStandardFileResponse));
        System.arraycopy(returnStatusBytes(readStandardFileResponse), 0, response, 0, 2);
        return Arrays.copyOf(readStandardFileResponse, readStandardFileResponse.length - 2);
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
            writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
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
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
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
// this method                                      | difference
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
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
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
     * section for value files
     */

    private boolean createValueFile(TextView logTextView, byte fileNumber, byte[] response) {
        // create a value file within the application
        byte createValueFileCommand = (byte) 0xcc;
        // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
        byte commSettingsByte = 0; // plain communication without any encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
        byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
        byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) 0x12; // Read Access & Write Access
                /*
                There are four different Access Rights (2 bytes for each file) stored for each file within
                each application:
                - Read Access
                - Write Access
                - Read&Write Access
                - ChangeAccessRights
                 */

        // create a value file in the new application: fileNo=6, cs=3
        //ar1 = 0x00;  // RW|CAR
        //ar2 = 0x00;  // R|W

        byte[] createValueFileParameters = new byte[17]; // just to show the length
        createValueFileParameters = new byte[]{
                fileNumber, commSettingsByte, accessRightsRwCar, accessRightsRW,
                10, 0, 0, 0,  // lower limit: 10
                90, 0, 0, 0,  // upper limit: 90
                50, 0, 0, 0,  // initial value: 50
                0  // limitedCredit operation disabled
        };
        writeToUiAppend(logTextView, printData("createValueFileParameters", createValueFileParameters));
        byte[] createValueFileResponse = new byte[0];
        try {
            createValueFileResponse = isoDep.transceive(wrapMessage(createValueFileCommand, createValueFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("createValueFileResponse", createValueFileResponse));
        System.arraycopy(returnStatusBytes(createValueFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createValueFileResponse", createValueFileResponse));
        if (checkDuplicateError(createValueFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createValueFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private int readFromValueFile(TextView logTextView, byte fileNumber, byte[] response) {
        // we read from a standard file within the selected application
        byte readValueFileCommand = (byte) 0x6c;
        byte[] readValueFileResponse = new byte[0];
                /*
                // DESFireEv1:
                byte[] apdu = new byte[7];
                apdu[0] = (byte) 0x90;
                apdu[1] = readValueFileCommand;
                apdu[2] = 0x00;
                apdu[3] = 0x00;
                apdu[4] = 0x01;
                apdu[5] = fileNumber;
                apdu[6] = 0x00;
                */
        try {
            readValueFileResponse = isoDep.transceive(wrapMessage(readValueFileCommand, new byte[]{fileNumber}));
            //readValueFileResponse = isoDep.transceive(apdu);
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return 0;
        }
        writeToUiAppend(logTextView, printData("readValueFileResponse", readValueFileResponse));
        // readValueFileResponse length: 6 data: 320000009100
        if (readValueFileResponse.length > 2) {
            System.arraycopy(returnStatusBytes(readValueFileResponse), 0, response, 0, 2);
            byte[] valueBytes = Arrays.copyOf(readValueFileResponse, readValueFileResponse.length - 2);
            int value = byteArrayLength4InversedToInt(valueBytes);
            writeToUiAppend(logTextView, "Actual value: " + value);
            return value;
        }
        return 0;
    }

    // this method does not check any boundaries defined in CreateValueFile. If error code BE occurs the method returns false
    private boolean increaseValueFile(TextView logTextView, byte fileNumber, int increaseValue, byte[] response) {
        // sanity checks
        if (increaseValue < 0) return false;
        if (increaseValue > 50) return false;
        byte creditValueCommand = (byte) 0x0c;
        // convert credit amount to a 4 byte reversed array
        byte[] creditValueAmountByte = intToLsb(increaseValue);
        byte[] creditValueFileParameters = new byte[5];
        creditValueFileParameters[0] = fileNumber;
        System.arraycopy(creditValueAmountByte, 0, creditValueFileParameters, 1, 4);
        writeToUiAppend(readResult, printData("creditValueFileParameters", creditValueFileParameters));
        byte[] creditValueFileResponse = new byte[0];
        try {
            creditValueFileResponse = isoDep.transceive(wrapMessage(creditValueCommand, creditValueFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("creditValueFileResponse", creditValueFileResponse));
        System.arraycopy(returnStatusBytes(creditValueFileResponse), 0, response, 0, 2);
        if (checkResponse(creditValueFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    // decrease by a positive value
    private boolean decreaseValueFile(TextView logTextView, byte fileNumber, int decreaseValue, byte[] response) {
        // sanity checks
        if (decreaseValue < 0) return false;
        if (decreaseValue > 50) return false;
        byte debitValueCommand = (byte) 0xdc;
        // convert credit amount to a 4 byte reversed array
        byte[] debitValueAmountByte = intToLsb(decreaseValue);
        byte[] debitValueFileParameters = new byte[5];
        debitValueFileParameters[0] = fileNumber;
        System.arraycopy(debitValueAmountByte, 0, debitValueFileParameters, 1, 4);
        writeToUiAppend(logTextView, printData("debitValueFileParameters", debitValueFileParameters));
        byte[] debitValueFileResponse = new byte[0];
        try {
            debitValueFileResponse = isoDep.transceive(wrapMessage(debitValueCommand, debitValueFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("debitValueFileResponse", debitValueFileResponse));
        System.arraycopy(returnStatusBytes(debitValueFileResponse), 0, response, 0, 2);
        if (checkResponse(debitValueFileResponse)) {
            return true;
        } else {
            return false;
        }
    }


    /**
     * section for cyclic files
     */

    /**
     * create cyclic file - this is using a FIXED key number 1 for read and write access
     * So don't forget that your application does need a minimum of 2 keys
     * The number of records is FIXED to 6 (5 entries + 1 spare entry)
     * The size of a record is FIXED to 32 bytes
     *
     * @param logTextView
     * @param fileNumber
     * @param response
     * @return
     */
    private boolean createCyclicFile(TextView logTextView, byte fileNumber, byte[] response) {
        // create the CyclicRecordFile
        byte createCyclicFileCommand = (byte) 0xc0;
        final byte RECORD_SIZE = (byte) 0x20; // 32 bytes
        final byte NUMBER_OF_RECORDS = (byte) 0x06;
        byte commSettingsByte = 0; // plain communication without any encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
        byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
        // here we are using key 1 for every access !
        //byte accessRightsRwCar = (byte) 0x11; // Read&Write Access & ChangeAccessRights
        //byte accessRightsRW = (byte) 0x11; // Read Access & Write Access

        // here we are using key 0 for every access !
        byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) 0x00; // Read Access & Write Access

                /*
                There are four different Access Rights (2 bytes for each file) stored for each file within
                each application:
                - Read Access
                - Write Access
                - Read&Write Access
                - ChangeAccessRights
                 */

        // create a value file in the new application: fileNo=6, cs=3
        //ar1 = 0x00;  // RW|CAR
        //ar2 = 0x00;  // R|W

        /* @param payload	10-byte array with the following contents:
         * 					<br>file number (1 byte),
         * 					<br>communication settings (1 byte),
         * 					<br>access rights (2 bytes: RW||CAR||R||W),
         * 					<br>size of a single record size (3 bytes LSB),
         * 					<br>maximum amount of records (3 bytes LSB)
         * @return			{@code true} on success, {@code false} otherwise
         * @throws IOException
         */

        byte[] createCyclicFileParameters = new byte[10]; // just to show the length
        createCyclicFileParameters = new byte[]{
                fileNumber, commSettingsByte, accessRightsRwCar, accessRightsRW,
                RECORD_SIZE, 0, 0,   // size of record fixed to dec 32
                NUMBER_OF_RECORDS, 0, 0 // maximum amount of records, fixed to dec 6
        };

        writeToUiAppend(logTextView, printData("createCyclicFileParameters", createCyclicFileParameters));
        byte[] createCyclicFileResponse = new byte[0];
        try {
            createCyclicFileResponse = isoDep.transceive(wrapMessage(createCyclicFileCommand, createCyclicFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        System.arraycopy(returnStatusBytes(createCyclicFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createCyclicFileResponse", createCyclicFileResponse));
        if (checkDuplicateError(createCyclicFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createCyclicFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean createCyclicFileEncryptedCommunication(TextView logTextView, byte fileNumber, byte[] response) {
        // create the CyclicRecordFile
        byte createCyclicFileCommand = (byte) 0xc0;
        final byte RECORD_SIZE = (byte) 0x20; // 32 bytes
        final byte NUMBER_OF_RECORDS = (byte) 0x06;
        byte commSettingsByte = (byte) 0x03; // encrypted communication
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
        byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
        // here we are using key 1 for every access !
        //byte accessRightsRwCar = (byte) 0x11; // Read&Write Access & ChangeAccessRights
        //byte accessRightsRW = (byte) 0x11; // Read Access & Write Access

        // here we are using key 0 for every access !
        byte accessRightsRwCar = (byte) 0x00; // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) 0x00; // Read Access & Write Access

                /*
                There are four different Access Rights (2 bytes for each file) stored for each file within
                each application:
                - Read Access
                - Write Access
                - Read&Write Access
                - ChangeAccessRights
                 */

        // create a value file in the new application: fileNo=6, cs=3
        //ar1 = 0x00;  // RW|CAR
        //ar2 = 0x00;  // R|W

        /* @param payload	10-byte array with the following contents:
         * 					<br>file number (1 byte),
         * 					<br>communication settings (1 byte),
         * 					<br>access rights (2 bytes: RW||CAR||R||W),
         * 					<br>size of a single record size (3 bytes LSB),
         * 					<br>maximum amount of records (3 bytes LSB)
         * @return			{@code true} on success, {@code false} otherwise
         * @throws IOException
         */

        byte[] createCyclicFileParameters = new byte[10]; // just to show the length
        createCyclicFileParameters = new byte[]{
                fileNumber, commSettingsByte, accessRightsRwCar, accessRightsRW,
                RECORD_SIZE, 0, 0,   // size of record fixed to dec 32
                NUMBER_OF_RECORDS, 0, 0 // maximum amount of records, fixed to dec 6
        };

        writeToUiAppend(logTextView, printData("createCyclicFileParameters", createCyclicFileParameters));
        byte[] createCyclicFileResponse = new byte[0];
        try {
            createCyclicFileResponse = isoDep.transceive(wrapMessage(createCyclicFileCommand, createCyclicFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        System.arraycopy(returnStatusBytes(createCyclicFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createCyclicFileResponse", createCyclicFileResponse));
        if (checkDuplicateError(createCyclicFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createCyclicFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean writeToCyclicFile(TextView logTextView, byte fileNumber, byte[] response) {
        // write to the CyclicFile
        byte writeFileCommand = (byte) 0x3b;
        // byte fileNumberLogCyclicFile; // is defined as constant
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
        byte[] dataLength;
        String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
        int contentLengthInt = contentString.length();
        // todo be more universal with this. The created record size is 32 so this data is fitting into one record
        byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
        byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
        byte[] writeFileParameters = new byte[(contentLengthInt + 7)];
        writeFileParameters[0] = fileNumber;
        System.arraycopy(offset, 0, writeFileParameters, 1, 3);
        System.arraycopy(contentLength, 0, writeFileParameters, 4, 3);
        System.arraycopy(content, 0, writeFileParameters, 7, contentLengthInt);
        writeToUiAppend(logTextView, printData("writeFileParameters", writeFileParameters));
        byte[] writeFileResponse = new byte[0];
        try {
            writeFileResponse = isoDep.transceive(wrapMessage(writeFileCommand, writeFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeFileResponse", writeFileResponse));
        System.arraycopy(returnStatusBytes(writeFileResponse), 0, response, 0, 2);
        if (checkResponse(writeFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean writeToCyclicFileEncrypted(TextView logTextView, byte fileNumber, byte[] response) {
        // write to the CyclicFile with AES encrypted data
        byte writeFileCommand = (byte) 0x3b;
        // byte fileNumberLogCyclicFile; // is defined as constant
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
        byte[] dataLength;
        String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
        int contentLengthInt = contentString.length();
        // todo be more universal with this. The created record size is 32 so this data is fitting into one record
        byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
        byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
        byte[] writeFileParameters = new byte[(contentLengthInt + 7)];
        writeFileParameters[0] = fileNumber;
        System.arraycopy(offset, 0, writeFileParameters, 1, 3);
        System.arraycopy(contentLength, 0, writeFileParameters, 4, 3);
        System.arraycopy(content, 0, writeFileParameters, 7, contentLengthInt);
        writeToUiAppend(logTextView, printData("writeFileParameters", writeFileParameters));

        // encryption part
        // as the first 7 bytes (fileNumber (1), offset (3) and length (3)) are not encrypted the encryptionOffset is 7
        ktype = KeyType.AES;
        iv = new byte[16];
        int encryptionOffset = 2;
        // missing 1 byte at the end ? for encryption ?
        byte[] encryptedWriteFileParameters = preprocessAes(writeFileParameters, encryptionOffset);
        writeToUiAppend(logTextView, printData("encrypted writeFileParameters", encryptedWriteFileParameters));

        encryptionOffset = 7;
        // for encryption we are working with the wrapped message
        byte[] encryptedWrappedMessage;
        try {
            byte[] wrappedMessage = wrapMessage(writeFileCommand, writeFileParameters);
            writeToUiAppend(logTextView, printData("wrappedMessage", wrappedMessage));
            encryptedWrappedMessage = preprocessAes(wrappedMessage, encryptionOffset);
            writeToUiAppend(logTextView, printData("encryptedWrappedMessage", encryptedWrappedMessage));
        } catch (Exception e) {
            writeToUiAppend(logTextView, "wrapMessage failed: " + e.getMessage());
            return false;
        }



/*
encryptionOffset = 7:
          writeFileParameters length: 37 data: 02 000000 1e0000 456e747279 2066726f6d20323032332e30342e32372031303a32313a3134                  Length 30
encrypted writeFileParameters length: 45 data: 02 000000 270000 456e747279 a05fe591daa82fbca3e9456a4e53377ef19a23f93c890bfeb226da6a0b7ace5500  Length 38

encryptionOffset = 2:
          writeFileParameters length: 37 data: 02 000000 1e0000 456e747279 2066726f6d20323032332e30342e32372031303a33303a3238
encrypted writeFileParameters length: 56 data: 02 000000 320000 8a3486660a1958c18f2f0bef8c708a4f4253e3f56b3f9b20f44c6c687ee1dae10b84344cfe36368df37048395fe6198900

using the complete wrapped message as basis
encryptionOffset = 10:
         wrappedMessage length: 43 data: 903b00002502 000000 1e0000 456e74 72792066726f6d20323032332e30342e32372031303a34343a313400
encryptedWrappedMessage length: 48 data: 903b00002a02 000000 1e0000 456e74 8d200b9eb13c837df58a1c522e43832f6ed459c5439d2cfe09335443cab8ff1500
writeFileResponse length: 2 data: 91af
encryptionOffset = 7:
         wrappedMessage length: 43 data: 903b00002502 000000 1e0000 456e7472792066726f6d20323032332e30342e32372031303a34393a303300
encryptedWrappedMessage length: 61 data: 903b00003702 000000 1e0000 5e62d29abcf02048b369b6ae0ba030693e03963931845cd5e5730a1cceec9bccaa290362df1e5277846a6acb82afffaa00
writeFileResponse length: 2 data: 917e length error


 */

        // is there an 0x00 at the end from somewhere ? delete it
        byte[] encryptedWrappedMessageTrimmed = Arrays.copyOf(encryptedWrappedMessage, (encryptedWrappedMessage.length - 1));
        writeToUiAppend(logTextView, printData("encryptedWrappedMes l-1", encryptedWrappedMessageTrimmed));



        byte[] writeFileResponse = new byte[0];
        try {
            //writeFileResponse = isoDep.transceive(wrapMessage(writeFileCommand, writeFileParameters));
            //writeFileResponse = isoDep.transceive(wrapMessage(writeFileCommand, encryptedWriteFileParameters));
            //writeFileResponse = isoDep.transceive(encryptedWrappedMessage);
            writeFileResponse = isoDep.transceive(encryptedWrappedMessageTrimmed);
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("writeFileResponse", writeFileResponse));
        System.arraycopy(returnStatusBytes(writeFileResponse), 0, response, 0, 2);
        if (checkResponse(writeFileResponse)) {
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

    private boolean commitWriteToFile(TextView logTextView, byte[] response) {
        // don't forget to commit all changes
        byte commitCommand = (byte) 0xc7;
        byte[] commitResponse = new byte[0];
        try {
            commitResponse = isoDep.transceive(wrapMessage(commitCommand, null));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("commitResponse", commitResponse));
        System.arraycopy(returnStatusBytes(commitResponse), 0, response, 0, 2);
        if (checkResponse(commitResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private byte[] readFromCyclicFile(TextView logTextView, byte fileNumber, byte[] recordNumber, byte[] numberOfRecords, byte[] response, boolean firstRun) {
        // read from to the CyclicFile
        byte[] readFileParameters = new byte[7];
        byte readFileCommand;
        if (firstRun) {
            readFileCommand = (byte) 0xbb;
            // byte fileNumberLogCyclicFile; // is defined as constant
            // File No
            //Record number (3 bytes)
            //Number of records (3 bytes)
            //byte[] readFileParameters = new byte[7];

            // compare desfire vs this
            //                              | file number
            //                                 | record number
            //                                        | number of records
            // read comm:     90 bb 0000 07 01 000000 000020 00
            // 1 record:      90 BB 0000 07 01 000000 000001 00
            //                90 BB 00 0007 01 000000 000001 00

            // my manua comm: 90 bb 0000 07 04 040000 010000 00


            readFileParameters[0] = fileNumber;
            System.arraycopy(recordNumber, 0, readFileParameters, 1, 3);
            System.arraycopy(numberOfRecords, 0, readFileParameters, 4, 3);
            writeToUiAppend(logTextView, printData("readFileParameters", readFileParameters));
        } else {
            // this is the follow up part after a ... 0xAF response
            readFileCommand = (byte) 0xaf;
            readFileParameters = null;
        }
        byte[] readFileResponse = new byte[0];
        try {
            // todo remove line
            writeToUiAppend(logTextView, printData("read Cycl comm", wrapMessage(readFileCommand, readFileParameters)));

            readFileResponse = isoDep.transceive(wrapMessage(readFileCommand, readFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
        }
        // todo copy readFileResponse to response

        return readFileResponse;
    }

    private boolean clearRecordFile(TextView logTextView, byte fileNumber, byte[] response) {
        // clear the CyclicFile
        byte clearFileCommand = (byte) 0xeb;
        byte[] clearFileParameters = new byte[1];
        clearFileParameters[0] = fileNumber;
        byte[] clearFileResponse;
        try {
            clearFileResponse = isoDep.transceive(wrapMessage(clearFileCommand, clearFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
            return false;
        }
        writeToUiAppend(logTextView, printData("clearFileResponse", clearFileResponse));
        System.arraycopy(returnStatusBytes(clearFileResponse), 0, response, 0, 2);
        if (checkResponse(clearFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    private byte[] getFileSettingsRecord(TextView logTextView, byte fileNumber, byte[] response) {
        byte getFileSettingsCommand = (byte) 0xf5;
        byte[] getFileSettingsParameters = new byte[1];
        getFileSettingsParameters[0] = fileNumber;
        byte[] getFileSettingsResponse;
        try {
            getFileSettingsResponse = isoDep.transceive(wrapMessage(getFileSettingsCommand, getFileSettingsParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
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
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
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

    private byte[] sendRequest(byte command, byte[] parameters) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        byte[] recvBuffer = isoDep.transceive(wrapMessage(command, parameters));

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