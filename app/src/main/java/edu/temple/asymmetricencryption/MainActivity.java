package edu.temple.asymmetricencryption;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.security.KeyPair;

import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity {

    Button getKeyPairButton;
    Button encryptButton;
    Button decryptButton;
    EditText inputText;
    EncryptionService encryptionService;
    Boolean connected = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        getKeyPairButton = findViewById(R.id.getKeyPairButton);
        encryptButton = findViewById(R.id.encryptButton);
        decryptButton = findViewById(R.id.decryptButton);
        inputText = findViewById(R.id.inputText);

        getKeyPairButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                encryptionService.getKeyPair(serviceHandler);
                Toast.makeText(MainActivity.this, "Key Pair Generated", Toast.LENGTH_LONG);
            }
        });

        encryptButton.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                if(connected) {
                    String text = inputText.getText().toString();
                    try {
                        encryptionService.cipher.init(Cipher.ENCRYPT_MODE, encryptionService.privateKey);
                        byte[] encryptedText = encryptionService.cipher.doFinal(text.getBytes());
                        inputText.setText(Base64.encodeToString(encryptedText, Base64.DEFAULT));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                else{
                    Toast.makeText(MainActivity.this, "Encryption service not connected", Toast.LENGTH_LONG);
                }
            }
        });

        decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                if(connected) {
                    byte[] encryptedText = Base64.decode(inputText.getText().toString(), Base64.DEFAULT);

                    try {
                        encryptionService.cipher.init(Cipher.DECRYPT_MODE, encryptionService.publicKey);
                        String text = new String(encryptionService.cipher.doFinal(encryptedText));
                        inputText.setText(text);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                else{
                    Toast.makeText(MainActivity.this, "Encryption service not connected", Toast.LENGTH_LONG);
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
}
