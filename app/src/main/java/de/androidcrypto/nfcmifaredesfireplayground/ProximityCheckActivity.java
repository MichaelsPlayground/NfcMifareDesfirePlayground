package de.androidcrypto.nfcmifaredesfireplayground;

import static com.github.skjolber.desfire.libfreefare.MifareDesfire.mifare_desfire_tag_new;

import static nfcjlib.core.DESFireEV1.validateKey;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;
import com.github.skjolber.desfire.ev1.model.DesfireTag;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;
import com.github.skjolber.desfire.libfreefare.MifareTag;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import nfcjlib.core.DESFireAdapter;
import nfcjlib.core.DESFireEV1;
import nfcjlib.core.KeyType;
import nfcjlib.core.util.AES;
import nfcjlib.core.util.TripleDES;

public class ProximityCheckActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {


    //Button vcConfKeySettings, vcConfKeySet;
    Button pcGetVcConfigKeyVersion, pcSetVcConfigurationKeyDes, pcSetVcConfigurationKeyAes;
    Button pcGetVcProxKeyVersion, pcSetVcProxKey;
    Button pcAuthWithVcConfKey, pcAuthWithVcProxKey;

    Button pcSelectMasterApplication, pcAuthMasterApplicationDes, pcAuthMasterApplicationAes;

    Button pcChangeMasterKeyToDes;

    Button btn38;

    EditText pcResult;

    EditText tagId;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte;
    IsoDep isoDep;
    Tag tagSaved;

    private DesfireTag desfireTag;
    //private DefaultIsoDepAdapter defaultIsoDepAdapter;
    DESFireEV1 desfire = new DESFireEV1();
    private DESFireAdapter desFireAdapter;

    /**
     * The following constants are global defined and got updated through several steps on ENCRYPTION and DECRYPTION
     */

    private final byte[] AID_Master = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00};
    byte AID_Master_AES_KEY_NUMBER = (byte) 0x00;
    byte[] DES_KEY = new byte[8]; // for the master application
    byte DES_KEY_NUMBER = (byte) 0x00;
    byte[] AES_KEY = new byte[16]; // for the master application
    //byte AES_KEY_NUMBER = (byte) 0x00;
    byte[] OLD_DES_KEY = new byte[16];
    byte[] VC_CONFIG_KEY = new byte[16];
    byte VC_CONFIG_KEY_NUMBER = (byte) 0x20;
    byte[] VC_PROXIMITY_KEY = new byte[16];
    byte VC_PROXIMITY_KEY_NUMBER = (byte) 0x21;

    private KeyType ktype;    // type of key used for authentication
    private byte[] iv;        // the IV, kept updated between operations (for 3K3DES/AES)
    private byte[] skey;      // session key: set on successful authentication

    //private byte[] ivOwn;        // the IV, kept updated between operations (for AES)
    //private byte[] skeyOwn;      // session key: set on successful authentication

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_proximity_check);

        System.out.println("*** btn vcConfKeySettings ***");

        tagId = findViewById(R.id.etPcTagId);

        //pcGetVcConfigKeyVersion = findViewById(R.id.btnVcConfKeyVersion);
        //pcGetVcProxKeyVersion = findViewById(R.id.btnVcProxKeyVersion);
        pcGetVcConfigKeyVersion = findViewById(R.id.btnGetVcConfKeyVersion);
        pcGetVcProxKeyVersion = findViewById(R.id.btnGetVcProxKeyVersion);

        pcSelectMasterApplication = findViewById(R.id.btnSelectMasterApplication);
        pcAuthMasterApplicationDes = findViewById(R.id.btnAuthMasterApplicationDes);
        pcAuthMasterApplicationAes = findViewById(R.id.btnAuthMasterApplicationAes);

        pcAuthWithVcConfKey = findViewById(R.id.btnAuthVcConfKey);
        pcAuthWithVcProxKey = findViewById(R.id.btnAuthVcProxKey);



        pcSetVcConfigurationKeyDes = findViewById(R.id.btnVcConfKeySetDes);
        pcSetVcConfigurationKeyAes = findViewById(R.id.btnVcConfKeySetAes);

        pcSetVcProxKey = findViewById(R.id.btnVcProxKeySet);

        pcChangeMasterKeyToDes = findViewById(R.id.btnChangeMasterKeyToDes);


        pcResult = findViewById(R.id.etPcResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        /**
         * section for getting the key versions of the VC Configuration and Proximity keys
         */

        pcGetVcConfigKeyVersion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will show the settings
                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "get the VC configuration key version (0x20)");

                try {
                    byte keyVersion = desfire.getKeyVersion(VC_CONFIG_KEY_NUMBER);
                    writeToUiAppend(pcResult, "getVcConfKeyVersion: " + keyVersion);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on getKeyVersion: " + e.getMessage());
                } catch (NullPointerException e) {
                    writeToUiAppend(pcResult, "NP Exception on getKeyVersion: " + e.getMessage());
                }
            }
        });

        pcGetVcProxKeyVersion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will show the settings
                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "get the VC proximity check key version (0x21)");

                try {
                    byte keyVersion = desfire.getKeyVersion(VC_PROXIMITY_KEY_NUMBER);
                    writeToUiAppend(pcResult, "getVcProxKeyVersion: " + keyVersion);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on getKeyVersion: " + e.getMessage());
                } catch (NullPointerException e) {
                    writeToUiAppend(pcResult, "NP Exception on getKeyVersion: " + e.getMessage());
                }
            }
        });

        /**
         * section for selecting the Master Application 0x00 00 00 and authentication with DES and AES
         */

        pcSelectMasterApplication.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // select the master application only
                byte[] response = new byte[2];
                boolean result = selectApplicationDes(pcResult, AID_Master, response);
                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "selectMasterApplication result: " + result + " with response: " + Utils.bytesToHex(response));
                if (!result) {
                    writeToUiAppend(pcResult, "the selectMasterApplication was not successful, aborted");
                    return;
                }
            }
        });

        pcAuthMasterApplicationDes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "DES auth the master application with PICC master key");

                try {
                    boolean result = desfire.authenticate(DES_KEY, DES_KEY_NUMBER, KeyType.DES);
                    writeToUiAppend(pcResult, "DES authenticate the Master Application result: " + result);
                    skey = desfire.getSkey();
                    iv = desfire.getIv();
                    writeToUiAppend(pcResult, printData("skey", skey));
                    writeToUiAppend(pcResult, printData("iv", iv));
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on DES authenticate the Master Application: " + e.getMessage());
                } catch (NullPointerException e) {
                    writeToUiAppend(pcResult, "NP Exception on DES authenticate the Master Application: " + e.getMessage());
                }

            }
        });

        /*
        pcAuthMasterApplicationDes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // auth the master application with a DES key
                byte[] response = new byte[2];


                writeToUiAppend(pcResult,"");
                // this is the raw version
                // do DES auth
                try {
                    String getChallengeCommand = "901a0000010000";
                    //String getChallengeCommand = "9084000000"; // IsoGetChallenge

                    //byte[] getChallengeResponse = nfcA.transceive(Utils.hexStringToByteArray(getChallengeCommand));
                    //byte[] getChallengeResponse = nfcA.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) 0x01} ));
                    byte[] getChallengeResponse = isoDep.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) 0x00}));
                    writeToUiAppend(pcResult, "getChallengeResponse: " + Utils.bytesToHex(getChallengeResponse));
                    // cf5e0ee09862d90391af
                    // 91 af at the end shows there is more data

                    byte[] challenge = Arrays.copyOf(getChallengeResponse, getChallengeResponse.length - 2);
                    writeToUiAppend(pcResult, "challengeResponse: " + Utils.bytesToHex(challenge));

                    // Of course the rndA shall be a random number,
                    // but we will use a constant number to make the example easier.
                    byte[] rndA = Utils.hexStringToByteArray("0001020304050607");
                    writeToUiAppend(pcResult, printData("rndA", rndA));

                    // This is the default key for a blank DESFire card.
                    // defaultKey = 8 byte array = [0x00, ..., 0x00]
                    byte[] defaultDESKey = Utils.hexStringToByteArray("0000000000000000");
                    byte[] IV = new byte[8];

                    // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
                    byte[] rndB = decrypt(challenge, defaultDESKey, IV);
                    writeToUiAppend(pcResult, printData("rndB", rndB));
                    // Rotate left the rndB byte[] leftRotatedRndB = rotateLeft(rndB);
                    byte[] leftRotatedRndB = rotateLeft(rndB);
                    writeToUiAppend(pcResult, printData("leftRotatedRndB", leftRotatedRndB));
                    // Concatenate the RndA and rotated RndB byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
                    byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
                    writeToUiAppend(pcResult, printData("rndA_rndB", rndA_rndB));

                    // Encrypt the bytes of the last step to get the challenge answer byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
                    IV = challenge;
                    byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
                    writeToUiAppend(pcResult, printData("challengeAnswer", challengeAnswer));

                    IV = Arrays.copyOfRange(challengeAnswer, 8, 16);

                    byte[] challengeAnswerAPDU = new byte[22];
                    challengeAnswerAPDU[0] = (byte) 0x90; // CLS
                    challengeAnswerAPDU[1] = (byte) 0xAF; // INS
                    challengeAnswerAPDU[2] = (byte) 0x00; // p1
                    challengeAnswerAPDU[3] = (byte) 0x00; // p2
                    challengeAnswerAPDU[4] = (byte) 0x10; // data length: 16 bytes
                    challengeAnswerAPDU[challengeAnswerAPDU.length - 1] = (byte) 0x00;
                    System.arraycopy(challengeAnswer, 0, challengeAnswerAPDU, 5, challengeAnswer.length);
                    writeToUiAppend(pcResult, printData("challengeAnswerAPDU", challengeAnswerAPDU));


                    byte[] challengeAnswerResponse = isoDep.transceive(challengeAnswerAPDU);
                    // response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
                    writeToUiAppend(pcResult, printData("challengeAnswerResponse", challengeAnswerResponse));
                    byte[] challengeAnswerResp = Arrays.copyOf(challengeAnswerResponse, getChallengeResponse.length - 2);
                    writeToUiAppend(pcResult, printData("challengeAnswerResp", challengeAnswerResp));

                    // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
                    //byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
                    byte[] rotatedRndAFromCard = decrypt(challengeAnswerResp, defaultDESKey, IV);
                    writeToUiAppend(pcResult, printData("rotatedRndAFromCard", rotatedRndAFromCard));

                    // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
                    byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
                    writeToUiAppend(pcResult, printData("rndAFromCard", rndAFromCard));
                    writeToUiAppend(pcResult, "********** AUTH RESULT **********");
                    if (Arrays.equals(rndA, rndAFromCard)) {
                        writeToUiAppend(pcResult, "Authenticated");
                    } else {
                        writeToUiAppend(pcResult, "Authentication failes");
                        //System.err.println(" ### Authentication failed. ### ");
                        //log("rndA:" + toHexString(rndA) + ", rndA from Card: " + toHexString(rndAFromCard));
                    }
                    writeToUiAppend(pcResult, "********** AUTH RESULT END **********");

                } catch (IOException e) {
                    writeToUiAppend(pcResult, "ERROR: IOException " + e.toString());
                    e.printStackTrace();
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "ERROR: Exception " + e.toString());
                    e.printStackTrace();
                }
            }
        });
        */

        pcAuthMasterApplicationAes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "AES auth the master application with PICC master key");

                try {
                    boolean result = desfire.authenticate(AES_KEY, AID_Master_AES_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult, "authenticate the Master Application result: " + result);
                    skey = desfire.getSkey();
                    iv = desfire.getIv();
                    writeToUiAppend(pcResult, printData("skey", skey));
                    writeToUiAppend(pcResult, printData("iv", iv));
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on authenticate the Master Application: " + e.getMessage());
                } catch (NullPointerException e) {
                    writeToUiAppend(pcResult, "NP Exception on authenticate the Master Application: " + e.getMessage());
                }

                /*

                // after changing the VC Configuration key the master application needs an AES authentication
                byte[] response = new byte[2];

                boolean result = false;
                try {
                    result = authenticate(AES_KEY, AES_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult,"");
                    writeToUiAppend(pcResult, "authenticateMasterApplication result: " + result);
                    writeToUiAppend(pcResult, printData("sessionKey", skey));

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "ERROR: IOException " + e.toString());
                }

                 */
            }
        });

        /**
         * section for authenticate the VC Configuration key (and Proximity key)
         */

        pcAuthWithVcConfKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // run an AES authorization with the VcConfigKey
                /*
                writeToUiAppend(pcResult, "authenticate the VC Config key (0x20)");
                byte[] response = new byte[0];
                boolean result = authenticateAes(pcResult, VC_CONFIG_KEY_NUMBER, VC_CONFIG_KEY, true, response);
                writeToUiAppend(pcResult, "Auth VC CONFIGURATION KEY result: " + result);
                writeToUiAppend(pcResult, printData("response", response));
*/

                try {
                    writeToUiAppend(pcResult,"");
                    writeToUiAppend(pcResult,"authenticate with VC Configuration key");
                    writeToUiAppend(pcResult, printData("pre skey", desfire.getSkey()));
                    writeToUiAppend(pcResult, printData("pre iv", desfire.getIv()));
                    writeToUiAppend(pcResult,"set the skey and empty IV");
                    //desfire.setSkey(skey);
                    //desfire.setIv(new byte[16]);
                    boolean result = desfire.authenticate(VC_CONFIG_KEY, VC_CONFIG_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult, "Auth VC CONFIGURATION KEY result: " + result);
                    writeToUiAppend(pcResult, printData("skey", desfire.getSkey()));
                    writeToUiAppend(pcResult, printData("iv", desfire.getIv()));
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on auth key: " + e.getMessage());
                } catch (NullPointerException e) {
                    writeToUiAppend(pcResult, "NP Exception on getKeyVersion: " + e.getMessage());
                }

            }
        });

        pcAuthWithVcProxKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // run an AES authorization with the VcConfigKey

                try {
                    boolean result = desfire.authenticate(VC_PROXIMITY_KEY, VC_PROXIMITY_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult,"");
                    writeToUiAppend(pcResult, "Auth VC PROXIMITY KEY result: " + result);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on auth key: " + e.getMessage());
                } catch (NullPointerException e) {
                    writeToUiAppend(pcResult, "NP Exception on getKeyVersion: " + e.getMessage());
                }

            }
        });







        pcSetVcConfigurationKeyDes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will set a new key
                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "write the VC configuration key (0x20) DES");

                //byte[] oldKey = new byte[16];

                try {
                    /*
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(pcResult, "dfSelectMasterApplication result: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(DES_KEY, DES_KEY_NUMBER, KeyType.DES);
                    writeToUiAppend(pcResult, "dfAuthenticateMasterApplication result: " + dfAuthM);
                    skey = desfire.getSkey();
                    writeToUiAppend(pcResult, printData("sessionkey", skey));
                     */

                    //desfire.setKtype(KeyType.AES);
                    writeToUiAppend(pcResult, printData("pre skey", desfire.getSkey()));
                    writeToUiAppend(pcResult, printData("pre IV", desfire.getIv()));
                    boolean result = desfire.changeKey(VC_CONFIG_KEY_NUMBER, (byte) 0, KeyType.AES, VC_CONFIG_KEY, OLD_DES_KEY);
                    writeToUiAppend(pcResult, "set VC configuration Key: " + result);
                    writeToUiAppend(pcResult, printData("after skey", desfire.getSkey()));
                    writeToUiAppend(pcResult, printData("after IV", desfire.getIv()));
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on set VC configuration Key: " + e.getMessage());
                }


            }
        });

        pcSetVcConfigurationKeyAes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will set a new key
                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "write the VC configuration key (0x20) AES");

                byte[] oldKey = new byte[16];

                try {
                    /*
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(pcResult, "dfSelectMasterApplication result: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(AES_KEY, AES_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult, "dfAuthenticateMasterApplication result: " + dfAuthM);
                    byte[] sessionKey = desfire.getSkey();
                    writeToUiAppend(pcResult, printData("sessionkey", sessionKey));
*/
                    //desfire.setSkey(skey);
                    //desfire.setIv(new byte[16]);
                    //desfire.setKtype(KeyType.AES);

                    writeToUiAppend(pcResult, printData("pre skey", desfire.getSkey()));
                    writeToUiAppend(pcResult, printData("pre IV", desfire.getIv()));
                    //boolean result = desfire.changeKeyWithoutValidation(VC_CONFIG_KEY_NUMBER, (byte) 0, KeyType.AES, VC_CONFIG_KEY, oldKey, skey);
                    boolean result = desfire.changeKey(VC_CONFIG_KEY_NUMBER, (byte) 0, KeyType.AES, VC_CONFIG_KEY, oldKey);
                    writeToUiAppend(pcResult, printData("after skey", desfire.getSkey()));
                    writeToUiAppend(pcResult, printData("after IV", desfire.getIv()));
                    writeToUiAppend(pcResult, "setKey: " + result);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on setKey: " + e.getMessage());
                }
            }
        });





        pcSetVcProxKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will set a new key
                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "write the VC proximity key (0x21)");

                byte[] oldKey = new byte[16];

                try {
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(pcResult, "dfSelectMasterApplication result: " + dfSelectM);


                    boolean dfAuthM = desfire.authenticate(AES_KEY, VC_CONFIG_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult, "df Authenticate ConfigKey result: " + dfAuthM);
                    byte[] sessionKey = desfire.getSkey();
                    writeToUiAppend(pcResult, printData("sessionkey", sessionKey));
                    byte[] iv = desfire.getIv();
                    writeToUiAppend(pcResult, printData("iv", iv));

/*
                    boolean dfAuthM = desfire.authenticate(AES_KEY, AES_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult, "df Authenticate MasterKey result: " + dfAuthM);
                    byte[] sessionKey = desfire.getSkey();
                    writeToUiAppend(pcResult, printData("sessionkey", sessionKey));
*/

                    desfire.setKtype(KeyType.AES);
                    boolean result = desfire.changeKeyWithoutValidation(VC_PROXIMITY_KEY_NUMBER, (byte) 0, KeyType.AES, VC_PROXIMITY_KEY, oldKey, sessionKey);
                    writeToUiAppend(pcResult, "setKey: " + result);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on setKey: " + e.getMessage());
                }


            }
        });

        pcChangeMasterKeyToDes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // as I irregularly change my cards master key to AES this method will change the key back to DES
                writeToUiAppend(pcResult,"");
                writeToUiAppend(pcResult, "change the MasterApplicationKey to DES (0x00)");
                byte[] oldKey = new byte[16];

                try {
                    //boolean result = desfire.changeKeyWithoutValidation(VC_CONFIG_KEY_NUMBER, (byte) 0, KeyType.AES, VC_CONFIG_KEY, oldKey, skey);
                    boolean result = desfire.changeKey(AID_Master_AES_KEY_NUMBER, (byte) 0, KeyType.DES, DES_KEY, AES_KEY);
                    writeToUiAppend(pcResult, "set MasterApplicationKey to DES: " + result);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on set MasterApplicationKey to DES: " + e.getMessage());
                }
            }
        });


/*
        btn38.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // set the AES keys for proximity check
                // works on EV2 and EV3 only !

                // see http://www.domcc3.com/assets/pdfs/Celiano_overclocking-proximity-checks.pdf
                // as we need AES encryption we use the Desfire methods

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

                    // complete reading
                    byte[] AID_Master = new byte[0];
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(pcResult, "dfSelectM result: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(desKey, (byte) 0, KeyType.DES);
                    writeToUiAppend(pcResult, "dfAuthMRead result: " + dfAuthM);

                    byte[] AES_KEY_VC2X_ZERO = Utils.hexStringToByteArray("00000000000000000000000000000000");
                    byte[] AES_KEY_VC2X = Utils.hexStringToByteArray("BB000000000000000000000000000000");

                    // get key settings for key 0x20
                    DesfireApplicationKeySettings keySettings00 = desfire.getKeySettings();
                    writeToUiAppend(pcResult, "keySettings00: " + keySettings00.toString());

                    // change key 20
                    // boolean changeKey(byte keyNo, KeyType newType, byte[] newKey, byte[] oldKey)
                    byte key20 = (byte) 0x20;
                    boolean changeKey20Result = desfire.changeKey(key20, KeyType.AES, AES_KEY_VC2X, AES_KEY_VC2X_ZERO);
                    writeToUiAppend(pcResult, "changeKey20Result: " + changeKey20Result);
                    // change key 21
                    // boolean changeKey(byte keyNo, KeyType newType, byte[] newKey, byte[] oldKey)
                    byte key21 = (byte) 0x21;
                    boolean changeKey21Result = desfire.changeKey(key21, KeyType.AES, AES_KEY_VC2X, AES_KEY_VC2X_ZERO);
                    writeToUiAppend(pcResult, "changeKey21Result: " + changeKey21Result);


                } catch (IOException e) {
                    writeToUiAppend(pcResult, "IOEx Error with DESFireEV1 + " + e.getMessage());
                } catch (Exception e) {
                    writeToUiAppend(pcResult, "Ex Error with DESFireEV1 + " + e.getMessage());
                }




            }
        });
*/
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

    private byte[] returnStatusBytes(byte[] data) {
        return Arrays.copyOfRange(data, (data.length - 2), data.length);
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
     * this is my own authentication DES method
     */

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

        writeToUiAppend(pcResult, printData("1st message exchange send", apdu));
        responseAPDU = isoDep.transceive(apdu);
        writeToUiAppend(pcResult, printData("1st message exchange resp", responseAPDU));
        //this.code = getSW2(responseAPDU);
        //feedback(apdu, responseAPDU);
        //if (getSW2(responseAPDU) != 0xAF) return false;

        //byte[] responseData = getData(responseAPDU);
        byte[] responseData = Arrays.copyOf(responseAPDU, responseAPDU.length - 2);
        // step 3
        //byte[] randB = recv(key, getData(responseAPDU), type, iv0);
        byte[] randB = recv(key, responseData, type, iv0);
        writeToUiAppend(pcResult, "step 3");
        writeToUiAppend(pcResult, printData("randB", randB));
        writeToUiAppend(pcResult, printData("iv0", iv0));

        if (randB == null)
            return false;
        byte[] randBr = rotateLeft(randB);
        writeToUiAppend(pcResult, printData("rotate left randB", randB));

        byte[] randA = new byte[randB.length];

        //fillRandom(randA);
        // we are using a static randA
        randA = Utils.hexStringToByteArray("000102030405060708090a0b0c0d0e0f");
        writeToUiAppend(pcResult, printData("randA", randA));

        // step 3: encryption
        writeToUiAppend(pcResult, "encryption");
        byte[] plaintext = new byte[randA.length + randBr.length];
        System.arraycopy(randA, 0, plaintext, 0, randA.length);
        System.arraycopy(randBr, 0, plaintext, randA.length, randBr.length);
        writeToUiAppend(pcResult, printData("plaintext randA|randB", plaintext));
        byte[] iv1 = Arrays.copyOfRange(responseData,
                responseData.length - iv0.length, responseData.length);
        writeToUiAppend(pcResult, printData("iv1", iv1));
        byte[] ciphertext = send(key, plaintext, type, iv1);
        if (ciphertext == null)
            return false;
        writeToUiAppend(pcResult, printData("ciphertext", ciphertext));
        // 2nd message exchange
        writeToUiAppend(pcResult, "2nd message exchange");
        apdu = new byte[5 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = (byte) 0xAF;
        apdu[4] = (byte) ciphertext.length;
        System.arraycopy(ciphertext, 0, apdu, 5, ciphertext.length);
        //responseAPDU = transmit(apdu);
        responseAPDU = isoDep.transceive(apdu);
        writeToUiAppend(pcResult, printData("2nd message exchange send", apdu));
        writeToUiAppend(pcResult, printData("2nd message exchange resp", responseAPDU));
        //this.code = getSW2(responseAPDU);
        //feedback(apdu, responseAPDU);
        //if (getSW2(responseAPDU) != 0x00) return false;

        // step 5
        byte[] iv2 = Arrays.copyOfRange(ciphertext,
                ciphertext.length - iv0.length, ciphertext.length);
        writeToUiAppend(pcResult, printData("iv2", iv2));
        byte[] responseData2 = Arrays.copyOf(responseAPDU, responseAPDU.length - 2);
        writeToUiAppend(pcResult, printData("responseData2", responseData2));
        byte[] randAr = recv(key, responseData2, type, iv2);
        writeToUiAppend(pcResult, printData("randAr", randAr));
        //byte[] randAr = recv(key, getData(responseAPDU), type, iv2);

        if (randAr == null)
            return false;
        byte[] randAr2 = rotateLeft(randA);
        writeToUiAppend(pcResult, printData("rotate left randAr", randAr2));
        for (int i = 0; i < randAr2.length; i++)
            if (randAr[i] != randAr2[i])
                return false;
        writeToUiAppend(pcResult, "compare both randA values");
        writeToUiAppend(pcResult, printData("randA Original", randA));
        writeToUiAppend(pcResult, printData("randA Or. rot ", randAr2));
        writeToUiAppend(pcResult, printData("randAr Receivt", randAr));

        // step 6
        skey = generateSessionKey(randA, randB, type);
        writeToUiAppend(pcResult, printData("sessionKey", skey));

        //this.ktype = type;
        //this.kno = keyNo;
        //this.iv = iv0;
        //this.skey = skey;

        return true;
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
     * section for authentication with aes keys
     */

    // if verbose = true all steps are printed out
    private boolean authenticateAes(TextView logTextView, byte keyId, byte[] key, boolean verbose, byte[] response) {
        try {
            writeToUiAppend(logTextView, "authenticateAes for keyId " + keyId + " and key " + Utils.bytesToHex(key));
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
                //ivOwn = new byte[16]; // AES IV is 16 bytes long
                //skeyOwn = generateSessionKey(rndA, rndB, KeyType.AES);
                //writeToUiAppend(logTextView, printData("## ivOwn ##", ivOwn));
                //writeToUiAppend(logTextView, printData("## session key ##", skeyOwn));
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
                /*
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is IsoDep compatible",
                            Toast.LENGTH_SHORT).show();
                });
                 */

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                runOnUiThread(() -> {
                    pcResult.setText("");
                    pcResult.setBackgroundColor(getResources().getColor(R.color.white));
                });

                // enhanced function
                //DefaultIsoDepWrapper isoDepWrapper = new DefaultIsoDepWrapper(isoDep);
                //defaultIsoDepAdapter = new DefaultIsoDepAdapter(isoDepWrapper, false);
                IsoDepWrapper isoDepWrapper1 = new DefaultIsoDepWrapper(isoDep);
                desFireAdapter = new DESFireAdapter(isoDepWrapper1, true);

                //nfcA.connect();
                isoDep.connect();

                // enhanced functions
                //nfcjTag = mifare_desfire_tag_new();
                //nfcjTag.setActive(1);
                //nfcjTag.setIo(defaultIsoDepAdapter);
                //nfcjTag.setIo(isoDepWrapper1);
                desfireTag = new DesfireTag();
                desfire = new DESFireEV1();
                desfire.setAdapter(desFireAdapter);

                System.out.println("*** tagId: " + Utils.bytesToHex(tag.getId()));

                // tag ID
                tagIdByte = tag.getId();
                runOnUiThread(() -> {
                    tagId.setText(Utils.bytesToHex(tagIdByte));
                });

                writeToUiAppend(pcResult, "card detected");

            }

        } catch (IOException e) {
            writeToUiAppend(pcResult, "ERROR: IOException " + e.toString());
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

/*
        writeToUiAppend(pcResult, "SignatureVerified: " + signatureVerfied);
        runOnUiThread(() -> {
            if (signatureVerfied) {
                pcResult.setBackgroundColor(getResources().getColor(R.color.light_background_green));
            } else {
                pcResult.setBackgroundColor(getResources().getColor(R.color.light_background_red));
            }
        });

 */
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