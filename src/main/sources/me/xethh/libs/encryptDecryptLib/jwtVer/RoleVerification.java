package me.xethh.libs.encryptDecryptLib.jwtVer;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import static me.xethh.libs.encryptDecryptLib.jwtVer.JWTVerificationBuilder.ISSUER;

public interface RoleVerification {
    boolean isOfType(DecodedJWT token, TokenType tokenType);

    default boolean anyOf(DecodedJWT token, TokenType... tokenTypes){
        for(TokenType tokenType : tokenTypes){
            if(isOfType(token, tokenType)){
                return true;
            }
        }
        return false;
    }

    default boolean noneOf(DecodedJWT token, TokenType... tokenTypes){
        for(TokenType tokenType : tokenTypes){
            if(isOfType(token, tokenType)){
                return false;
            }
        }
        return true;
    }
    default boolean isAdmin(DecodedJWT token) {
        return isOfType(token, TokenType.admin);
    }
    default boolean notAdmin(DecodedJWT token) {
        return !isOfType(token, TokenType.admin);
    }

    boolean justValid(DecodedJWT token);

    default boolean justNotValid(DecodedJWT token){
        return !justValid(token);
    }

    static RoleVerification instance(Algorithm algorithm){
        return instance(algorithm, ISSUER);
    }
    static RoleVerification instance(Algorithm algorithm, String issuer){
        return new RoleVerification() {
            @Override
            public boolean isOfType(DecodedJWT token, TokenType tokenType) {
                try{
                    JWT.require(algorithm)
                            .withIssuer(issuer)
                            .withClaim("type", TokenType.admin.name())
                            .build()
                            .verify(token);
                    return true;
                } catch (Throwable throwable){
                    return false;
                }
            }

            @Override
            public boolean justValid(DecodedJWT token) {
                try{
                    JWT.require(algorithm)
                            .withIssuer(issuer)
                            .build()
                            .verify(token);
                    return true;
                }catch (Throwable throwable){
                    return false;
                }
            }
        };
    }
}
