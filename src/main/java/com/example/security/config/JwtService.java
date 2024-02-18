package com.example.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "4f61c0398a80c744dbe43d0515dc01c28ea35415210764f2034a75c780bf021dd94233b94e5d19090f4b70f869e245cd5395528eef917ab45fea6a9e8554ca46'";
    public String extractUsername (String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public String generateToken (UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken (
        Map<String, Object> extractClaims,
        UserDetails userDetails
    ) {
        return Jwts
            .builder()
            .setClaims(extractClaims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date (System.currentTimeMillis() + 1000 * 60 * 24))
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    public boolean isTokenValid (String jwtToken, UserDetails userDetails) {
        final String username = extractUsername(jwtToken);
        return username.equals (userDetails.getUsername());
    }

    public boolean isTokenExpired (String jwtToken) {
        return extractExpiration (jwtToken).before (new Date());
    }

    public Date extractExpiration (String jwtToken) {
        return extractClaim (jwtToken, Claims::getExpiration);
    }
    public <T> T extractClaim (String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply (claims);
    }

    private Claims extractAllClaims (String jwtToken) {
        return Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey())
            .build()
            .parseClaimsJws(jwtToken)
            .getBody();
    }

    private Key getSignInKey () {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
