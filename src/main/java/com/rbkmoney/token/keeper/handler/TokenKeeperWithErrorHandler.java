package com.rbkmoney.token.keeper.handler;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.AuthDataNotFound;
import com.rbkmoney.token.keeper.Scope;
import com.rbkmoney.token.keeper.exception.TokenEncryptionException;
import com.rbkmoney.token.keeper.factory.AuthDataFactory;
import com.rbkmoney.token.keeper.mg.repository.AuthDataRepository;
import com.rbkmoney.token.keeper.service.JweTokenGenerator;
import lombok.extern.slf4j.Slf4j;
import org.apache.thrift.TException;

import java.util.Map;

import static com.rbkmoney.token.keeper.util.ParametersChecker.checkBadParameters;

@Slf4j
public class TokenKeeperWithErrorHandler extends TokenKeeperHandler {

    public TokenKeeperWithErrorHandler(AuthDataFactory authDataFactory, JweTokenGenerator<AuthData> jweTokenGenerator, AuthDataRepository authDataRepository) {
        super(authDataFactory, jweTokenGenerator, authDataRepository);
    }

    @Override
    public AuthData create(Scope scope, Map<String, String> metadata, String subjectId, String realm) throws TException {
        try {
            log.info("Request create scope: {} metadata: {} subjectId: {} realm: {}", scope, metadata, subjectId, realm);
            AuthData authData = super.create(scope, metadata, subjectId, realm);
            log.info("Response: {}", authData);
            return authData;
        } catch (TokenEncryptionException e) {
            log.error("Error when create e: ", e);
            throw new TException(e.getMessage());
        } catch (Exception e) {
            log.error("Error when create e: ", e);
            throw new TException("Internal service error e: " + e.getMessage());
        }
    }

    @Override
    public AuthData createWithExpiration(Scope scope, Map<String, String> metadata, String subjectId, String realm,
                                         String expirationTime) throws TException {
        try {
            log.info("Request createWithExpiration scope: {} metadata: {} subjectId: {} realm: {} expirationTime: {}",
                    scope, metadata, subjectId, realm, expirationTime);
            checkBadParameters(expirationTime, "Bad request parameters, expiration required and not empty arg!");
            AuthData authData = super.createWithExpiration(scope, metadata, subjectId, realm, expirationTime);
            log.info("Response: {}", authData);
            return authData;
        } catch (TokenEncryptionException e) {
            log.error("Error when createWithExpiration e: ", e);
            throw new TException(e.getMessage());
        } catch (Exception e) {
            log.error("Error when createWithExpiration e: ", e);
            throw new TException("Internal service error e: " + e.getMessage());
        }
    }

    @Override
    public AuthData getByToken(String jwe) throws TException {
        try {
            log.info("Request getByToken jwe: {}", jwe);
            checkBadParameters(jwe, "Bad request parameters, jwe required and not empty arg!");
            AuthData authData = super.getByToken(jwe);
            log.info("Response: {}", authData);
            return authData;
        } catch (TokenEncryptionException e) {
            log.error("Error when getByToken e: ", e);
            throw new TException(e.getMessage());
        } catch (AuthDataNotFound e) {
            log.error("Error when getByToken. Can't find data by this parameters! e: ", e);
            throw new AuthDataNotFound(e);
        } catch (Exception e) {
            log.error("Error when getByToken e: ", e);
            throw new TException("Internal service error e: " + e.getMessage());
        }
    }

    @Override
    public AuthData get(String tokenId) throws TException {
        try {
            log.info("Request get tokenId: {}", tokenId);
            checkBadParameters(tokenId, "Bad request parameters, tokenId required and not empty arg!");
            AuthData authData = super.get(tokenId);
            log.info("Response: {}", authData);
            return authData;
        } catch (AuthDataNotFound e) {
            log.error("Error when get. Can't find data by this parameters tokenId: {} e: ", tokenId, e);
            throw new AuthDataNotFound(e);
        } catch (Exception e) {
            log.error("Error when get e: ", e);
            throw new TException("Internal service error e: " + e.getMessage());
        }
    }

    @Override
    public void revoke(String tokenId) throws TException {
        try {
            log.info("Request revoke tokenId: {}", tokenId);
            checkBadParameters(tokenId, "Bad request parameters, tokenId required and not empty arg!");
            super.revoke(tokenId);
            log.info("Revoked tokenId: {}", tokenId);
        } catch (AuthDataNotFound e) {
            log.error("Error when revoke. Can't find data by this parameters tokenId: {} e: ", tokenId, e);
            throw new AuthDataNotFound(e);
        } catch (Exception e) {
            log.error("Error when revoke e: ", e);
            throw new TException("Internal service error e: " + e.getMessage());
        }
    }

}
