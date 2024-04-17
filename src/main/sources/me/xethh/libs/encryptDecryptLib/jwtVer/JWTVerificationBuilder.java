package me.xethh.libs.encryptDecryptLib.jwtVer;

import com.auth0.jwt.algorithms.Algorithm;

import java.security.interfaces.RSAPublicKey;

public class JWTVerificationBuilder {
    public static final String ISSUER = "root.auth.xethh.me";

    private final Algorithm algo;
    private final String issuer;

    public JWTVerificationBuilder(RSAPublicKey key) {
        this(Algorithm.RSA256(key));
    }

    public JWTVerificationBuilder(Algorithm algorithm) {
        this(algorithm, ISSUER);
    }


    public JWTVerificationBuilder(RSAPublicKey key, String issuer) {
        this(Algorithm.RSA256(key), issuer);
    }

    public JWTVerificationBuilder(Algorithm algo, String issuer) {
        this.algo = algo;
        this.issuer = issuer;
    }

    public Verification requireResource(SystemResource systemResource) {
        return new SimpleSystemResourceVerification(algo, issuer, systemResource);
    }
}
