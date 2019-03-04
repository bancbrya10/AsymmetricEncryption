package edu.temple.asymmetricencryption;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.util.Log;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class EncryptionService extends Service {
    Handler handler;
    IBinder myBinder = new CustomBinder();
    KeyPairGenerator kpg;
    KeyPair keys;
    Cipher cipher;
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;

    public EncryptionService() {
    }

    @Override
    public IBinder onBind(Intent intent) {
        return myBinder;
    }

    public class CustomBinder extends Binder {
        EncryptionService getService(){
            return EncryptionService.this;
        }
    }

    public void getKeyPair(final Handler handler){
        this.handler = handler;
        Thread t = new Thread() {
            @Override
            public void run(){
                try {
                    kpg = KeyPairGenerator.getInstance("RSA");
                    keys = kpg.generateKeyPair();
                    KeyFactory fact = KeyFactory.getInstance("RSA");
                    cipher = Cipher.getInstance("RSA");
                    privateKey = (RSAPrivateKey) keys.getPrivate();
                    publicKey = (RSAPublicKey) keys.getPublic();

                    String privateKeyString = privateKey.getPrivateExponent().toString();
                    String publicKeyString = publicKey.getPublicExponent().toString();

                    Log.d("Public", publicKeyString);
                    Log.d("Private", privateKeyString);
                    Log.d("Mod", publicKey.getModulus().toString());
                    RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(privateKey.getModulus(), new BigInteger(privateKeyString));
                    privateKey = (RSAPrivateKey) fact.generatePrivate(privKeySpec);
                    RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(publicKey.getModulus(), new BigInteger(publicKeyString));
                    publicKey = (RSAPublicKey) fact.generatePublic(pubKeySpec);

                    Message msg = Message.obtain();
                    msg.obj = keys;
                    handler.sendMessage(msg);
                }
                catch (Exception e){
                    Log.d("Key Pair Error", String.valueOf(e.getStackTrace()));
                }
            }
        };
        t.start();
        try {
            t.join();
        } catch (InterruptedException e) {
            Log.d("ServiceThreadError", "Error joining threads");
        }
    }
}
