package me.xethh.libs.encryptDecryptLib.jwtVer;

import com.auth0.jwt.interfaces.DecodedJWT;

public interface Verification{
    boolean verify(DecodedJWT token);
    default boolean forbiddened(DecodedJWT token){
        return !verify(token);
    }
}
