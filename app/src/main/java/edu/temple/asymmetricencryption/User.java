package edu.temple.asymmetricencryption;

import java.security.interfaces.RSAPublicKey;

public class User {

    RSAPublicKey publicKey;
    String username;

    public User(String username, RSAPublicKey publicKey){
        this.username = username;
        this.publicKey = publicKey;
    }

    public String getUsername(){
        return username;
    }

    public RSAPublicKey getPublicKey(){
        return publicKey;
    }
}
