package de.androidcrypto.nfcmifaredesfireplayground;

import static com.github.skjolber.desfire.libfreefare.MifareDesfire.mifare_desfire_tag_new;

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

public class ProximityCheckActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    //Button vcConfKeySettings, vcConfKeySet;
    Button pcGetVcConfigKeySettings, pcSetVcConfigurationKey;
    Button pcGetVcProxKeySettings, pcSetVcProxKey;
    Button authWithVcConfKey;

    Button btn38;

    EditText pcResult;

    EditText tagId;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte;
    IsoDep isoDep;
    Tag tagSaved;

    private DesfireTag desfireTag;
    //private DefaultIsoDepAdapter defaultIsoDepAdapter;
    private DESFireAdapter desFireAdapter;

    /**
     * The following constants are global defined and got updated through several steps on ENCRYPTION and DECRYPTION
     */

    private final byte[] AID_Master = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00};
    byte[] DES_KEY = new byte[8]; // for the master application
    byte[] VC_CONFIG_KEY = new byte[16];
    byte VC_CONFIG_KEY_NUMBER = (byte) 0x20;
    byte[] VC_PROXIMITY_KEY = new byte[16];
    byte VC_PROXIMITY_KEY_NUMBER = (byte) 0x21;

    private KeyType ktype;    // type of key used for authentication
    private byte[] iv;        // the IV, kept updated between operations (for 3K3DES/AES)
    private byte[] skey;      // session key: set on successful authentication

    private byte[] ivOwn;        // the IV, kept updated between operations (for AES)
    private byte[] skeyOwn;      // session key: set on successful authentication

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_proximity_check);

        System.out.println("*** btn vcConfKeySettings ***");

        tagId = findViewById(R.id.etPcTagId);

        pcGetVcConfigKeySettings = findViewById(R.id.btnVcConfKeySettings);
        pcSetVcConfigurationKey = findViewById(R.id.btnVcConfKeySet);
        pcGetVcProxKeySettings = findViewById(R.id.btnVcProxKeySettings);
        pcSetVcProxKey = findViewById(R.id.btnVcProxKeySet);
        authWithVcConfKey = findViewById(R.id.btnVcConfKeyAuth);

        pcResult = findViewById(R.id.etPcResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        pcGetVcConfigKeySettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will show the settings
                writeToUiAppend(pcResult, "get the VC configuration key settings (0x20)");

                DESFireEV1 desfire = new DESFireEV1();
                desfire.setAdapter(desFireAdapter);
                byte keyNumber = (byte) 0x20;
                try {
                    byte keyVersion = desfire.getKeyVersion(keyNumber);
                    writeToUiAppend(pcResult, "getKeyVersion: " + keyVersion);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on getKeyVersion: " + e.getMessage());
                }
            }
        });

        pcSetVcConfigurationKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will set a new key
                writeToUiAppend(pcResult, "write the VC configuration key (0x20)");
                DESFireEV1 desfire = new DESFireEV1();
                desfire.setAdapter(desFireAdapter);

                byte[] oldKey = new byte[16];

                try {
                    boolean dfSelectM = desfire.selectApplication(AID_Master);
                    writeToUiAppend(pcResult, "dfSelectMasterApplication result: " + dfSelectM);

                    boolean dfAuthM = desfire.authenticate(DES_KEY, (byte) 0, KeyType.DES);
                    writeToUiAppend(pcResult, "dfAuthenticateMasterApplication result: " + dfAuthM);
                    byte[] sessionKey = desfire.getSkey();
                    writeToUiAppend(pcResult, printData("sessionkey", sessionKey));

                    desfire.setKtype(KeyType.AES);
                    boolean result = desfire.changeKeyWithoutValidation(VC_CONFIG_KEY_NUMBER, (byte) 0, KeyType.AES, VC_CONFIG_KEY, oldKey, sessionKey);
                    writeToUiAppend(pcResult, "setKey: " + result);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on setKey: " + e.getMessage());
                }


            }
        });

        authWithVcConfKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // run an AES authorization with the VcConfigKey
                writeToUiAppend(pcResult, "authenticate the VC Config key (0x20)");
                byte[] response = new byte[0];
                boolean result = authenticateAes(pcResult, VC_CONFIG_KEY_NUMBER, VC_CONFIG_KEY, true, response);
                writeToUiAppend(pcResult, "Auth VC CONFIGURATION KEY result: " + result);
                writeToUiAppend(pcResult, printData("response", response));

                /*
                DESFireEV1 desfire = new DESFireEV1();
                desfire.setAdapter(desFireAdapter);
                try {
                    boolean result = desfire.authenticate(VC_CONFIG_KEY, VC_CONFIG_KEY_NUMBER, KeyType.AES);
                    writeToUiAppend(pcResult, "Auth VC CONFIGURATION KEY result: " + result);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on auth key: " + e.getMessage());
                }
                */
            }
        });

        pcGetVcProxKeySettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will show the settings
                writeToUiAppend(pcResult, "get the VC proximity check key settings (0x21)");

                DESFireEV1 desfire = new DESFireEV1();
                desfire.setAdapter(desFireAdapter);
                byte keyNumber = (byte) 0x21;
                try {
                    byte keyVersion = desfire.getKeyVersion(keyNumber);
                    writeToUiAppend(pcResult, "getKeyVersion: " + keyVersion);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(pcResult, "Exception on getKeyVersion: " + e.getMessage());
                } catch (NullPointerException e) {
                    writeToUiAppend(pcResult, "NPException on getKeyVersion: " + e.getMessage());
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