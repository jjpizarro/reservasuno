package edu.unimagdalena.reservasuno.security.jwt;

import edu.unimagdalena.reservasuno.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import java.security.Key;
import java.util.Date;
@Component
public class JwtUtil {
    private static Logger log = LoggerFactory.getLogger(JwtUtil.class);
    @Value("${app.jwt.secret}")
    private String jwtSecret;
    @Value("${app.jwt.expirationMs}")
    private String jwtExpirationMs;

    public String generateJwtToken(Authentication authentication){
        UserDetails userDetails = (UserDetailsImpl)authentication.getPrincipal();
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();

    }
    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parser()
                    .setSigningKey(key())
                    .build()
                    .parse(authToken);
            return true;
        }catch (MalformedJwtException e  ){
            log.error("Ivalid JWT token: {}",e.getMessage());
        }catch (ExpiredJwtException e){
            log.error("JWT token expired: {}", e.getMessage());
        }catch (UnsupportedJwtException e){
            log.error("JWT token is supported: {}", e.getMessage());
        }catch (IllegalArgumentException e){
            log.error("Jwt Claim string is empty: {}",e.getMessage());
        }
        return false;


    }
    public String getUsernameFromJwtToken(String token){
        return Jwts.parser().setSigningKey(key()).build()
                .parseClaimsJwt(token).getPayload().getSubject();
    }
    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

}
