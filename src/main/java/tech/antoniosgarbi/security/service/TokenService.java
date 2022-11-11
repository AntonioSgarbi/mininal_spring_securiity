package tech.antoniosgarbi.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenService {
    @Value("${security.token.access_expiration}")
    private Long accessExpiration;

    @Value("${security.token.refresh_expiration}")
    private Long refreshExpiration;

    @Value("${security.token.issuer}")
    private String issuer;

    @Value("${security.token.access_secret}")
    private String accessSecret;

    @Value("${security.token.refresh_secret}")
    private String refreshSecret;

    public Algorithm algorithm(String secret) {
        return Algorithm.HMAC256(secret);
    }

    public String gerarToken(UserDetails userDetails) {
        Date agora = new Date();
        Date expirar = new Date(agora.getTime() + accessExpiration);

        return JWT
                .create()
                .withSubject(userDetails.getUsername())
                .withExpiresAt(expirar)
                .withIssuer(this.issuer)
                .sign(this.algorithm(this.accessSecret));
    }

    public boolean validarAccessToken(String token) {
        return this.validarToken(token, this.accessSecret);
    }

    public boolean validarRefreshToken(String token) {
        return this.validarToken(token, this.refreshSecret);
    }

    private boolean validarToken(String token, String secret) {
        if(token == null) return false;

        try {
            JWT.require(this.algorithm(secret))
                    .withIssuer(this.issuer)
                    .build()
                    .verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }

    public String getUsernameFromToken(String jwt) {
        return JWT.decode(jwt).getSubject();
    }

    public String gerarRefreshToken(UserDetails userDetails) {
        Date agora = new Date();

        Date expirar = new Date(agora.getTime() + this.refreshExpiration);

        return JWT
                .create()
                .withSubject(userDetails.getUsername())
                .withExpiresAt(expirar)
                .withIssuer(this.issuer)
                .sign(this.algorithm(this.refreshSecret));
    }

}
