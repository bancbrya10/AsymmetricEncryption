package edu.temple.asymmetricencryption;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Parcelable;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.Cipher;

import static android.nfc.NdefRecord.createMime;

public class MainActivity extends AppCompatActivity {

    Button getKeyPairButton;
    Button sendKeyButton;
    Button sendMessageButton;
    EditText inputText;
    EditText usernameText;
    EncryptionService encryptionService;
    Boolean connected = false;
    NfcAdapter nfcAdapter;
    PublicKey currentKey;
    String partnerName = "";
    String username = "";
    Spinner spinner;
    UserAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        getKeyPairButton = findViewById(R.id.getKeyPairButton);
        sendKeyButton = findViewById(R.id.sendKeyButton);
        sendMessageButton = findViewById(R.id.sendMessageButton);
        inputText = findViewById(R.id.inputText);
        usernameText = findViewById(R.id.usernameEditText);
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        spinner = findViewById(R.id.spinner);
        encryptionService = new EncryptionService();

        adapter = new UserAdapter(this, encryptionService.users);
        spinner.setAdapter(adapter);

        if (nfcAdapter == null) {
            Toast.makeText(this, "NFC is not available", Toast.LENGTH_LONG).show();
            finish();
            return;
        }

        getKeyPairButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(connected) {
                    username = usernameText.getText().toString();
                    if (username.equals("")) {
                        Toast.makeText(MainActivity.this, "Please enter a username before sending a key", Toast.LENGTH_LONG).show();
                    } else {
                        encryptionService.getKeyPair(serviceHandler, username);
                        Toast.makeText(MainActivity.this, "Key Pair Generated", Toast.LENGTH_LONG).show();
                        while (!connected) ;
                        byte[] byteArr = Base64.encode(encryptionService.publicKey.getEncoded(), 0);
                        Log.d("KeyPairGenerated", new String(byteArr));
                        adapter.notifyDataSetChanged();
                    }
                }
                else{
                    Toast.makeText(MainActivity.this, "Encryption Service not Connected. Press \"Get Key Pair\" button before continuing.", Toast.LENGTH_LONG).show();
                }
            }
        });

        sendKeyButton.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
            @Override
            public void onClick(View v) {
                if(connected){
                    username = usernameText.getText().toString();
                    if(username.equals("")){
                        Toast.makeText(MainActivity.this, "Please enter a username before sending a key", Toast.LENGTH_LONG).show();
                    }
                    else {
                        JSONObject jsonObject = new JSONObject();
                        try {
                            jsonObject.put("username", username);
                            jsonObject.put("key", new String(Base64.encode(encryptionService.publicKey.getEncoded(),0)));
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }
                        nfcAdapter.setNdefPushMessage(createNdefMessage(jsonObject.toString()), MainActivity.this);
                        Log.d("KeyToSend", jsonObject.toString());
                    }
                }
                else {
                    Toast.makeText(MainActivity.this, "Encryption Service not Connected. Press \"Get Key Pair\" button before continuing.", Toast.LENGTH_LONG).show();
                }
            }
        });

        sendMessageButton.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
            @Override
            public void onClick(View v) {
                if(connected) {
                    if (username.equals("")) {
                        if(usernameText.getText().toString().equals("")){
                            Toast.makeText(MainActivity.this, "Please enter a username before sending a message", Toast.LENGTH_LONG).show();
                        }
                        else {
                            username = usernameText.getText().toString();
                            setEncryptedMessage();
                        }
                    }
                    else {
                        setEncryptedMessage();
                    }
                }
                else{
                    Toast.makeText(MainActivity.this, "Encryption Service not Connected. Press \"Get Key Pair\" button before continuing.", Toast.LENGTH_LONG).show();
                }
            }
        });
    }

    @Override
    protected void onStart() {
        super.onStart();
        Intent serviceIntent = new Intent(this, EncryptionService.class);
        bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onStop() {
        super.onStop();
        unbindService(serviceConnection);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            try {
                processIntent(getIntent());
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        setIntent(intent);
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    public NdefMessage createNdefMessage(String text) {
        NdefMessage msg = new NdefMessage(
                new NdefRecord[] {
                        createMime("application/edu.temple.asymmetricencryption", text.getBytes())
                        ,NdefRecord.createApplicationRecord("edu.temple.asymmetricencryption")
                });
        return msg;
    }

    void processIntent(Intent intent) throws JSONException {
        if(connected) {
            Parcelable[] rawMsgs = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
            // only one message sent during the beam
            NdefMessage msg = (NdefMessage) rawMsgs[0];
            // record 0 contains the MIME type, record 1 is the AAR, if present
            String receivedStr = new String(msg.getRecords()[0].getPayload());
            JSONObject jsonObject = new JSONObject(receivedStr);
            if(jsonObject.has("to")) {
                byte[] encryptedText = Base64.decode(jsonObject.getString("message"), Base64.DEFAULT);
                try {
                    encryptionService.cipher.init(Cipher.DECRYPT_MODE, currentKey);
                    String text = new String(encryptionService.cipher.doFinal(encryptedText));
                    inputText.setText(text);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            else {
                partnerName = jsonObject.getString("username");
                try {
                    String keyStr = jsonObject.getString("key");
                    X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(keyStr.getBytes());
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    currentKey = kf.generatePublic(X509publicKey);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                }
            }
        }
        else{
            Toast.makeText(MainActivity.this, "Encryption Service not Connected. Press \"Get Key Pair\" button before continuing.", Toast.LENGTH_LONG).show();
        }
    }

    ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            EncryptionService.CustomBinder binder = (EncryptionService.CustomBinder) service;
            encryptionService = binder.getService();
            connected = true;
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            connected = false;
        }
    };

    Handler serviceHandler = new Handler(new Handler.Callback() {
        @Override
        public boolean handleMessage(Message msg) {
            Log.d("Service Message", msg.obj.toString());
            return false;
        }
    });

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    private void setEncryptedMessage(){
        String text = inputText.getText().toString();
        try {
            encryptionService.cipher.init(Cipher.ENCRYPT_MODE, encryptionService.privateKey);
            byte[] encryptedText = encryptionService.cipher.doFinal(text.getBytes());
            inputText.setText(Base64.encodeToString(encryptedText, Base64.DEFAULT));
            if(partnerName.equals("")){
                Toast.makeText(MainActivity.this, "Please select a user to send the message to from the dropdown menu", Toast.LENGTH_LONG).show();
            }
            else{
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("to", partnerName);
                jsonObject.put("from", username);
                jsonObject.put("message", inputText.getText().toString());
                nfcAdapter.setNdefPushMessage(createNdefMessage(jsonObject.toString()), MainActivity.this);
                Log.d("MessageToSend", jsonObject.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private class getPartnersTask extends AsyncTask{

        JSONObject temp;

        @Override
        protected Object doInBackground(Object[] objects) {
            
            return null;
        }
    }
}
