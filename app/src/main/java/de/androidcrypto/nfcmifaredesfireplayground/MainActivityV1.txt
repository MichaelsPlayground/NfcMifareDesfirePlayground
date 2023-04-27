package de.androidcrypto.nfcmifaredesfireplayground;

import static com.github.skjolber.desfire.libfreefare.MifareDesfire.mifare_desfire_tag_new;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.github.skjolber.desfire.ev1.model.DesfireTag;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
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


public class MainActivityV1 extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    Button btn2, btn3, btn4, btn5, btn6, btn7, btn8, btn9, btn10, btn11, btn12, btn13, btn14, btn15, btn16, btn17;
    EditText tagId, dataToWrite, readResult;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte;
    IsoDep isoDep;

    // vars for enhanced functions using libraries from https://github.com/skjolber/desfire-tools-for-android
    private MifareTag nfcjTag;
    private DesfireTag desfireTag;
    private DefaultIsoDepAdapter defaultIsoDepAdapter;

    /**
     * Note on all KEY data (important for DES/TDES keys only)
     * A DES key has a length 64 bits (= 8 bytes) but only 56 bits are used for encryption, the remaining 8 bits are were
     * used as parity bits and within DESFire as key version information.
     * If you are using the 'original' key you will run into authentication issues.
     * You should always strip of the parity bits by running the setKeyVersion command
     * e.g. setKeyVersion(AID_DesLog_Key2_New, 0, AID_DesLog_Key2_New.length, (byte) 0x00);
     * This will set the key version to '0x00' by setting all parity bits to '0x00'
     */
    // some constants
    private final byte[] AID_Master = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00};
    private final byte AID_Master_number_of_keys = (byte) 0x01;
    private final byte[] AID_Master_Key0 =     Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte AID_Master_Key0_Number = (byte) 0x00;

    private final byte[] AID_DesStandard = new byte[]{(byte) 0xa9, (byte) 0xa8, (byte) 0xa1};
    private final byte AID_DesStandard_number_of_keys = (byte) 0x03;
    private final byte[] AID_DesStandard_Key0 =     Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this

    private final byte[] AID_DesValue = new byte[]{(byte) 0xa9, (byte) 0xa8, (byte) 0xa2};
    private final byte[] AID_DesLog = new byte[]{(byte) 0xa9, (byte) 0xa8, (byte) 0xa3}; // A3 A8 A9
    private final byte[] AID_DesLog_Key0 =     Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte AID_DesLog_Key0_Number = (byte) 0x00;
    private final byte[] AID_DesLog_Key1 =     Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte[] AID_DesLog_Key1_New = Utils.hexStringToByteArray("3322119988776601"); // new key, lets work on this
    private final byte AID_DesLog_Key1_Number = (byte) 0x01;
    private final byte[] AID_DesLog_Key2 =     Utils.hexStringToByteArray("0000000000000000"); // default key, lets work on this
    private final byte[] AID_DesLog_Key2_New = Utils.hexStringToByteArray("3322119988776602"); // new key, lets work on this
    private final byte[] AID_DesLog_Key2_New2 = Utils.hexStringToByteArray("3322119988776612"); // new key, lets work on this
    private final byte AID_DesLog_Key2_Number = (byte) 0x02;
    private final byte DesLogCyclicFileFileNumber = (byte) 0x03;
    private final byte numberOfRecordsLogCyclicFile = (byte) 0x06; // 5 records (+1 record as spare record for writing data before committing), fixed for this method

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
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        btn2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create application

                // first select application 00 00 00
                byte[] responseData = new byte[2];
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectApplication success: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
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
                writeToUiAppend(readResult, "createApplication success: " + createApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
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

                // first select application 00 00 00
                byte[] responseData = new byte[2];
                responseData = new byte[2];
                boolean selectApplicationSuccess = selectApplicationDes(readResult, AID_Master, responseData);
                writeToUiAppend(readResult, "selectApplication success: " + selectApplicationSuccess + " with response: " + Utils.bytesToHex(responseData));
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
                byte selectApplicationCommand = (byte) 0x5a;
                byte[] applicationIdentifier = new byte[]{(byte) 0xa1, (byte) 0xa2, (byte) 0xa3}; // AID is A3A2A1
                byte[] selectApplicationResponse = new byte[0];
                try {
                    selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("selectApplicationResponse", selectApplicationResponse));

                // we create a standard file within the application
                byte createStandardFileCommand = (byte) 0xcd;
                // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
                byte fileNumber = (byte) 07;
                byte commSettingsByte = 0; // todo check, this should be plain communication without any encryption
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
                byte[] fileSize = new byte[]{(byte) 0x20, (byte) 0xf00, (byte) 0x00}; // 32 bytes
                byte[] createStandardFileParameters = new byte[7];
                createStandardFileParameters[0] = fileNumber;
                createStandardFileParameters[1] = commSettingsByte;
                System.arraycopy(accessRights, 0, createStandardFileParameters, 2, 2);
                System.arraycopy(fileSize, 0, createStandardFileParameters, 4, 3);

                writeToUiAppend(readResult, printData("createStandardFileParameters", createStandardFileParameters));
                // createStandardFileParameters length: 7 data: 0700eeee200000

                byte[] createStandardFileResponse = new byte[0];
                try {
                    createStandardFileResponse = isoDep.transceive(wrapMessage(createStandardFileCommand, createStandardFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("createStandardFileResponse", createStandardFileResponse));
                // createStandardFileResponse length: 2 data: 9100
            }
        });

        btn5.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the free memory on the card
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

                // get the free memory on the card
                byte getFreeMemoryCommand = (byte) 0x6e;
                byte[] getFreeMemoryResponse = new byte[0];
                try {
                    getFreeMemoryResponse = isoDep.transceive(wrapMessage(getFreeMemoryCommand, null));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("getFreeMemoryResponse", getFreeMemoryResponse));
                // getFreeMemoryResponse length: 5 data: 400800 9100 (EV1 2K after create 1 app + 1 32 byte file)
                // getFreeMemoryResponse length: 5 data: 000a00 9100 (EV2 2K empty)
                // getFreeMemoryResponse length: 5 data: 001400 9100 (EV2 4K empty)
                // 400800 = 00 08 40 = 2112 bytes
                // 000a00 = 00 0a 00 = 2560 bytes
                // 001400 = 00 14 00 = 5120 bytes
                int length;
                if (getFreeMemoryResponse.length > 2) {
                    byte[] lengthBytes = Arrays.copyOf(getFreeMemoryResponse, getFreeMemoryResponse.length - 2);
                    length = byteArrayLength3InversedToInt(lengthBytes);
                    writeToUiAppend(readResult, "free memory on card: " + length);
                }
            }
        });

        btn6.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // read from file
                // first select application
                // first select application 00 00 00
                byte selectApplicationCommand = (byte) 0x5a;
                byte[] applicationIdentifier = new byte[]{(byte) 0xa1, (byte) 0xa2, (byte) 0xa3};
                byte[] selectApplicationResponse = new byte[0];
                try {
                    selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("selectApplicationResponse", selectApplicationResponse));

                // now read from file
                byte readStandardFileCommand = (byte) 0xbd;
                byte fileNumber = (byte) 07;
                byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // no offset
                byte[] length = new byte[]{(byte) 0x20, (byte) 0xf00, (byte) 0x00}; // 32 bytes
                byte[] readStandardFileParameters = new byte[7];
                readStandardFileParameters[0] = fileNumber;
                System.arraycopy(offset, 0, readStandardFileParameters, 1, 3);
                System.arraycopy(length, 0, readStandardFileParameters, 4, 3);

                writeToUiAppend(readResult, printData("readStandardFileParameters", readStandardFileParameters));
                // createStandardFileParameters length: 7 data: 0700eeee200000

                byte[] readStandardFileResponse = new byte[0];
                try {
                    readStandardFileResponse = isoDep.transceive(wrapMessage(readStandardFileCommand, readStandardFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("readStandardFileResponse", readStandardFileResponse));
                writeToUiAppend(readResult, "readStandardFileResponse: " + new String(readStandardFileResponse, StandardCharsets.UTF_8));
                // readStandardFileResponse length: 2 data: 9100
            }
        });

        btn7.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String data = dataToWrite.getText().toString();
                if (TextUtils.isEmpty(data)) {
                    Toast.makeText(getApplicationContext(),
                            "please enter some data to write on tag",
                            Toast.LENGTH_SHORT).show();
                    return;
                }
                // write to file
                // first select application
                byte selectApplicationCommand = (byte) 0x5a;
                byte[] applicationIdentifier = new byte[]{(byte) 0xa1, (byte) 0xa2, (byte) 0xa3};
                byte[] selectApplicationResponse = new byte[0];
                try {
                    selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("selectApplicationResponse", selectApplicationResponse));

                // now write to file
                byte[] dataByte = data.getBytes(StandardCharsets.UTF_8);
                byte writeStandardFileCommand = (byte) 0x3d;
                byte fileNumber = (byte) 07;
                int numberOfBytes = dataByte.length;
                byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // no offset
                byte[] length = new byte[]{(byte) (numberOfBytes & 0xFF), (byte) 0xf00, (byte) 0x00}; // 32 bytes
                byte[] writeStandardFileParameters = new byte[(7 + dataByte.length)]; // todo if encrypted we need to append the CRC
                writeStandardFileParameters[0] = fileNumber;
                System.arraycopy(offset, 0, writeStandardFileParameters, 1, 3);
                System.arraycopy(length, 0, writeStandardFileParameters, 4, 3);
                System.arraycopy(dataByte, 0, writeStandardFileParameters, 7, dataByte.length);

                writeToUiAppend(readResult, printData("writeStandardFileParameters", writeStandardFileParameters));
                // writeStandardFileParameters length: 19 data: 07000000200000546865206c617a7920646f67

                byte[] writeStandardFileResponse = new byte[0];
                try {
                    writeStandardFileResponse = isoDep.transceive(wrapMessage(writeStandardFileCommand, writeStandardFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("writeStandardFileResponse", writeStandardFileResponse));
                // writeStandardFileResponse length: 2 data: 9100
            }
        });

        btn8.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create value file
                // select application
                byte selectApplicationCommand = (byte) 0x5a;
                byte[] applicationIdentifier = new byte[]{(byte) 0xa1, (byte) 0xa2, (byte) 0xa3}; // AID is A3A2A1
                byte[] selectApplicationResponse = new byte[0];
                try {
                    selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("selectApplicationResponse", selectApplicationResponse));

                // create a value file within the application
                byte createValueFileCommand = (byte) 0xcc;
                // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
                byte fileNumber = (byte) 0x08;
                byte commSettingsByte = 0; // todo check, this should be plain communication without any encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
                byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
                byte accessRightsRwCar = (byte) 0xee; // Read&Write Access & ChangeAccessRights
                byte accessRightsRW = (byte) 0xee; // Read Access & Write Access
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

                writeToUiAppend(readResult, printData("createValueFileParameters", createValueFileParameters));
                //

                byte[] createValueFileResponse = new byte[0];
                try {
                    createValueFileResponse = isoDep.transceive(wrapMessage(createValueFileCommand, createValueFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("createValueFileResponse", createValueFileResponse));
                //
            }
        });

        btn9.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // increase value file

                // select application
                byte selectApplicationCommand = (byte) 0x5a;
                byte[] applicationIdentifier = new byte[]{(byte) 0xa1, (byte) 0xa2, (byte) 0xa3}; // AID is A3A2A1
                byte[] selectApplicationResponse = new byte[0];
                try {
                    selectApplicationResponse = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("selectApplicationResponse", selectApplicationResponse));

                // first read the existing value
                // check access rights, here not necessary because of free access

                byte readValueFileCommand = (byte) 0x6c;
                byte fileNumber = (byte) 0x08;
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
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("readValueFileResponse", readValueFileResponse));
                // readValueFileResponse length: 6 data: 320000009100

                if (readValueFileResponse.length > 2) {
                    byte[] valueBytes = Arrays.copyOf(readValueFileResponse, readValueFileResponse.length - 2);
                    int value = byteArrayLength4InversedToInt(valueBytes);
                    writeToUiAppend(readResult, "Actual value: " + value);
                }

                // now increase data
                byte creditValueCommand = (byte) 0x0c;
                int increaseValueBy3 = 3;
                // convert credit amount to a 4 byte reversed array
                byte[] creditValueAmountByte = intToLsb(increaseValueBy3);
                byte[] creditValueFileParameters = new byte[5];
                creditValueFileParameters[0] = fileNumber;
                System.arraycopy(creditValueAmountByte, 0, creditValueFileParameters, 1, 4);
                writeToUiAppend(readResult, printData("creditValueFileParameters", creditValueFileParameters));
                byte[] creditValueFileResponse = new byte[0];
                try {
                    creditValueFileResponse = isoDep.transceive(wrapMessage(creditValueCommand, creditValueFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("creditValueFileResponse", creditValueFileResponse));

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

                // now read again
                try {
                    readValueFileResponse = isoDep.transceive(wrapMessage(readValueFileCommand, new byte[]{fileNumber}));
                    //readValueFileResponse = isoDep.transceive(apdu);
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("readValueFileResponse", readValueFileResponse));
                // readValueFileResponse length: 6 data: 320000009100

                if (readValueFileResponse.length > 2) {
                    byte[] valueBytes = Arrays.copyOf(readValueFileResponse, readValueFileResponse.length - 2);
                    int value = byteArrayLength4InversedToInt(valueBytes);
                    writeToUiAppend(readResult, "Actual value: " + value);
                }

                // decrease value by 1
                byte debitValueCommand = (byte) 0xdc;
                int decreaseValueBy1 = 1;
                // convert credit amount to a 4 byte reversed array
                byte[] debitValueAmountByte = intToLsb(decreaseValueBy1);
                byte[] debitValueFileParameters = new byte[5];
                debitValueFileParameters[0] = fileNumber;
                System.arraycopy(debitValueAmountByte, 0, debitValueFileParameters, 1, 4);
                writeToUiAppend(readResult, printData("debitValueFileParameters", debitValueFileParameters));
                byte[] debitValueFileResponse = new byte[0];
                try {
                    debitValueFileResponse = isoDep.transceive(wrapMessage(debitValueCommand, debitValueFileParameters));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("debitValueFileResponse", debitValueFileResponse));

                // don't forget to commit all changes
                //byte commitCommand = (byte) 0xc7;
                //byte[] commitResponse = new byte[0];
                try {
                    commitResponse = isoDep.transceive(wrapMessage(commitCommand, null));
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("commitResponse", commitResponse));

                // now read again
                try {
                    readValueFileResponse = isoDep.transceive(wrapMessage(readValueFileCommand, new byte[]{fileNumber}));
                    //readValueFileResponse = isoDep.transceive(apdu);
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(readResult, "tranceive failed: " + e.getMessage());
                }
                writeToUiAppend(readResult, printData("readValueFileResponse", readValueFileResponse));
                // readValueFileResponse length: 6 data: 320000009100

                if (readValueFileResponse.length > 2) {
                    byte[] valueBytes = Arrays.copyOf(readValueFileResponse, readValueFileResponse.length - 2);
                    int value = byteArrayLength4InversedToInt(valueBytes);
                    writeToUiAppend(readResult, "Actual value: " + value);
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
                    desfire.setAdapter(defaultIsoDepAdapter);
                    // public boolean authenticate(byte[] key, byte keyNo, DesfireKeyType type) throws IOException {
                    boolean suc = desfire.authenticate(new byte[24], (byte) 0, DESFireEV1.DesfireKeyType.TKTDES);
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
                        numberOfRecordsLogCyclicFile, 0, 0 // maximum amount of records, fixed to dec 5
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
                success = authenticateApplicationDes(readResult, (byte) 0x01, AID_DesLog_Key1, responseData);
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
                boolean authenticateSuccess = authenticateApplicationDes(readResult, (byte) 0x01, AID_DesLog_Key1, responseData);
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
                    boolean writeToFileCommitSuccess = writeToFileCommit(readResult, responseData);
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
                    //writeToUiAppend(readResult, printData("readFileData", readFileData));
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
                    desFireEV1.setAdapter(defaultIsoDepAdapter);

                    // select an application
                    boolean sucSelectApplication = desFireEV1.selectApplication(AID_DesLog);
                    writeToUiAppend(readResult, "sucSelectApplication: " + sucSelectApplication);

                    // note: the access key settings for this application is 0x0F see M075031_desfire.pdf pages 33, 34 + 35
                    // createApplicationDes:
                    // byte applicationMasterKeySettings = (byte) 0x0f; - the leftmost bits are '0' so it is the appMasterKey ('00') that has tto get used for authorization

                    // authenticate with key 0
                    boolean sucAuthenticateAid = desFireEV1.authenticate(AID_DesLog_Key0, AID_DesLog_Key0_Number, DESFireEV1.DesfireKeyType.DES);
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
                    boolean sucChange =  desFireEV1.changeKey(AID_DesLog_Key2_Number, DESFireEV1.DesfireKeyType.DES, AID_DesLog_Key2_New, AID_DesLog_Key2);
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
                boolean authenticateSuccess = authenticateApplicationDes(readResult, AID_DesLog_Key1_Number, AID_DesLog_Key1, responseData);
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
                boolean commitSuccess = writeToFileCommit(readResult, responseData);
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
                writeToUiAppend(readResult,"");
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
                boolean authenticateMasterSuccess = authenticateApplicationDes(readResult, (byte) 0x00, AID_Master_Key0, responseData);
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


        // todo change key values
        // todo change numberOfKeys to '05 + 1'
        //

    }

    /**
     * start section for ready to use commands
     */

    /**
     * section for authentication with DES
     */

    private boolean authenticateApplicationDes(TextView logTextView, byte keyId, byte[] key, byte[] response) {
        try {
            writeToUiAppend(logTextView, "authenticateApplicationDes for keyId " + keyId + " and key " + Utils.bytesToHex(key));
            // do DES auth
            //String getChallengeCommand = "901a0000010000";
            //String getChallengeCommand = "9084000000"; // IsoGetChallenge

            //byte[] getChallengeResponse = nfcA.transceive(Utils.hexStringToByteArray(getChallengeCommand));
            //byte[] getChallengeResponse = nfcA.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) 0x01} ));
            byte[] getChallengeResponse = isoDep.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) (keyId & 0xFF)}));
            writeToUiAppend(logTextView,  printData("getChallengeResponse", getChallengeResponse));
            // cf5e0ee09862d90391af
            // 91 af at the end shows there is more data

            byte[] challenge = Arrays.copyOf(getChallengeResponse, getChallengeResponse.length - 2);
            writeToUiAppend(logTextView, printData("challengeResponse", challenge));

            // Of course the rndA shall be a random number,
            // but we will use a constant number to make the example easier.
            byte[] rndA = Utils.hexStringToByteArray("0001020304050607");
            writeToUiAppend(logTextView, printData("rndA", rndA));

            // This is the default key for a blank DESFire card.
            // defaultKey = 8 byte array = [0x00, ..., 0x00]
            //byte[] defaultDESKey = Utils.hexStringToByteArray("0000000000000000");
            byte[] defaultDESKey = key.clone();
            byte[] IV = new byte[8];

            // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
            byte[] rndB = decrypt(challenge, defaultDESKey, IV);
            writeToUiAppend(logTextView, printData("rndB", rndB));
            // Rotate left the rndB byte[] leftRotatedRndB = rotateLeft(rndB);
            byte[] leftRotatedRndB = rotateLeft(rndB);
            writeToUiAppend(logTextView, printData("leftRotatedRndB", leftRotatedRndB));
            // Concatenate the RndA and rotated RndB byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            writeToUiAppend(logTextView, printData("rndA_rndB", rndA_rndB));

            // Encrypt the bytes of the last step to get the challenge answer byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
            IV = challenge;
            byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
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
            writeToUiAppend(logTextView, printData("challengeAnswerAPDU", challengeAnswerAPDU));

            /*
             * Sending the APDU containing the challenge answer.
             * It is expected to be return 10 bytes [rndA from the Card] + 9100
             */
            byte[] challengeAnswerResponse = isoDep.transceive(challengeAnswerAPDU);
            // response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
            writeToUiAppend(logTextView, printData("challengeAnswerResponse", challengeAnswerResponse));
            byte[] challengeAnswerResp = Arrays.copyOf(challengeAnswerResponse, getChallengeResponse.length - 2);
            writeToUiAppend(logTextView, printData("challengeAnswerResp", challengeAnswerResp));

            /*
             * At this point, the challenge was processed by the card. The card decrypted the
             * rndA rotated it and sent it back.
             * Now we need to check if the RndA sent by the Card is valid.
             */// encrypted rndA from Card, returned in the last step byte[] encryptedRndAFromCard = response.getData();

            // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            //byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            byte[] rotatedRndAFromCard = decrypt(challengeAnswerResp, defaultDESKey, IV);
            writeToUiAppend(logTextView, printData("rotatedRndAFromCard", rotatedRndAFromCard));

            // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            writeToUiAppend(logTextView, printData("rndAFromCard", rndAFromCard));
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
            writeToUiAppend(logTextView, "authenticateApplicationDes tranceive failed: " + e.getMessage());
            writeToUiAppend(logTextView, "authenticateApplicationDes tranceive failed: " + Arrays.toString(e.getStackTrace()));
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

    /**
     * section for cyclic files
     */

    /**
     * create cyclic file - this is using a FIXED key number 1 for read and write access
     * So don't forget that your application does need a minimum of 2 keys
     * The number of records is FIXED to 6 (5 entries + 1 spare entry)
     * The size of a record is FIXED to 32 bytes
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

    private boolean writeToFileCommit(TextView logTextView, byte[] response) {
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
            readFileResponse = isoDep.transceive(wrapMessage(readFileCommand, readFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "tranceive failed: " + e.getMessage());
        }
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
     * @param a			1K/2K/3K 3DES
     * @param offset	start position of the key within a
     * @param length	key length
     * @param version	the 1-byte version
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
                DefaultIsoDepWrapper isoDepWrapper = new DefaultIsoDepWrapper(isoDep);
                defaultIsoDepAdapter = new DefaultIsoDepAdapter(isoDepWrapper, false);


                //nfcA.connect();
                isoDep.connect();

                // enhanced functions
                nfcjTag = mifare_desfire_tag_new();
                nfcjTag.setActive(1);
                nfcjTag.setIo(defaultIsoDepAdapter);
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