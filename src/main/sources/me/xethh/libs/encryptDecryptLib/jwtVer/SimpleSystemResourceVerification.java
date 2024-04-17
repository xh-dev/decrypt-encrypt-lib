package me.xethh.libs.encryptDecryptLib.jwtVer;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.*;

@Data
@Builder
@With
@NoArgsConstructor
@AllArgsConstructor
public class SimpleSystemResourceVerification implements Verification{
    private Algorithm algorithm;
    private String issuer;
    private SystemResource systemResource;

    @Override
    public boolean verify(DecodedJWT token) {
        try{
            JWT.require(algorithm)
                    .withIssuer(issuer)
                    .withClaim("type", TokenType.access.name())
                    .withClaim("roles", ((claim, decodedJWT) -> claim.asString().contains(systemResource.name())))
                    .build()
                    .verify(token);
            return true;
        } catch (Throwable throwable) {
            return false;
        }
    }

}
