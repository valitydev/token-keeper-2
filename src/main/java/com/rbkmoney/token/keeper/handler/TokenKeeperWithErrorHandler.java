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

/**
 * @author k.struzhkin on 11/21/18
 */
@Slf4j
public class TokenKeeperWithErrorHandler extends TokenKeeperHandler {

    public TokenKeeperWithErrorHandler(AuthDataFactory authDataFactory, JweTokenGenerator<AuthData> jweTokenGenerator, AuthDataRepository authDataRepository) {
        super(authDataFactory, jweTokenGenerator, authDataRepository);
    }

    @Override
    public AuthData create(Scope scope, Map<String, String> metadata, String subjectId, String realm) throws TException {
        try {
            return super.create(scope, metadata, subjectId, realm);
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
            checkBadParameters(expirationTime, "Bad request parameters, expiration required and not empty arg!");
            return super.createWithExpiration(scope, metadata, subjectId, realm, expirationTime);
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
            checkBadParameters(jwe, "Bad request parameters, jwe required and not empty arg!");
            return super.getByToken(jwe);
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
            checkBadParameters(tokenId, "Bad request parameters, tokenId required and not empty arg!");
            return super.get(tokenId);
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
            checkBadParameters(tokenId, "Bad request parameters, tokenId required and not empty arg!");
            super.revoke(tokenId);
        } catch (AuthDataNotFound e) {
            log.error("Error when revoke. Can't find data by this parameters tokenId: {} e: ", tokenId, e);
            throw new AuthDataNotFound(e);
        } catch (Exception e) {
            log.error("Error when revoke e: ", e);
            throw new TException("Internal service error e: " + e.getMessage());
        }
    }

}
