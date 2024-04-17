package me.xethh.libs.encryptDecryptLib.jwtVer;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

public interface Verification{
    boolean verify(DecodedJWT token);
    default boolean verify(String token) {
        return verify(JWT.decode(token));
    }
}
