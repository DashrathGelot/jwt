package com.dashspring;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class JWT {
    private static long EXPIRE_DURATION = 60 * 60 * 1000; //1 hour
    private String secretKey = "DASH-SPRING";
    private static JWT jwt;
    private JWT() {

    }

    public static JWT getInstance() {
        if (jwt == null) {
            jwt = new JWT();
        }
        return jwt;
    }

    public JWT setSecret(String secretKey) {
        this.secretKey = secretKey;
        return this;
    }

    public JWT setExpiry(long EXPIRE_DURATION) {
        JWT.EXPIRE_DURATION = EXPIRE_DURATION;
        return this;
    }

    public JWT(long EXPIRE_DURATION, String secretKey) {
        JWT.EXPIRE_DURATION = EXPIRE_DURATION;
        this.secretKey = secretKey;
    }

    public String getUserNameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(getAllClaimsFromToken(token));
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token) {
        return getExpirationDateFromToken(token).before(new Date());
    }

    public String generate(String userName) {
        Map<String, Object> claims = new HashMap<>();
        return generate(claims, userName);
    }

    public String generate(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_DURATION))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    public boolean validate(String token, String userName) {
        return userName.equals(getUserNameFromToken(token)) && !isTokenExpired(token);
    }

    public String validateAndGetUserName(String token) throws IllegalAccessException {
        String userName;
        try {
            userName = getUserNameFromToken(token);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unable to get JWT Token");
        } catch (ExpiredJwtException e) {
            throw new IllegalAccessException("JWT Token is expired");
        }
        if (validate(token, userName)) {
            return userName;
        } else {
            throw new IllegalAccessException("Not Valid JWT Token");
        }
    }
}
