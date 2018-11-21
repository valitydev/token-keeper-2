package com.rbkmoney.token.keeper.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.exception.TokenEncryptionException;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.text.ParseException;
import java.util.Base64;

/**
 * @author k.struzhkin on 11/21/18
 */
@Slf4j
@Service
public class JweTokenGeneratorImpl implements JweTokenGenerator<AuthData> {

    private static final ObjectMapper om = new ObjectMapper();
    private static final String AUTH_DATA = "authData";

    private final String secreteKey;

    public JweTokenGeneratorImpl(@Value("${jwe.secrete.key}") String secreteKey) {
        this.secreteKey = secreteKey;
    }

    @Override
    public String generate(AuthData authData) {
        try {
            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                    .claim(AUTH_DATA, authData)
                    .build();
            JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM);
            EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);
            byte[] decodedKey = Base64.getDecoder().decode(secreteKey);
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            AESEncrypter encrypter = new AESEncrypter(originalKey);
            jwt.encrypt(encrypter);
            return jwt.serialize();
        } catch (JOSEException e) {
            log.error("Error when generate token e: ", e);
            throw new TokenEncryptionException("Can't generate jwe e: " + e.getMessage());
        }
    }

    @Override
    public AuthData decode(String jwe) {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(secreteKey);
            EncryptedJWT parse = EncryptedJWT.parse(jwe);
            AESDecrypter aesDecrypter = new AESDecrypter(decodedKey);
            parse.decrypt(aesDecrypter);
            JSONObject authData = (JSONObject) parse.getJWTClaimsSet().getClaim(AUTH_DATA);
            return om.readValue(authData.toString(), AuthData.class);
        } catch (ParseException | JOSEException | IOException e) {
            log.error("Error when decode token e: ", e);
            throw new TokenEncryptionException("Can't decode jwe e: " + e.getMessage());
        }
    }
}
