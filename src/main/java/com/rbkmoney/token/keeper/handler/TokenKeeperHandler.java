package com.rbkmoney.token.keeper.handler;

import com.google.common.base.Strings;
import com.rbkmoney.token.keeper.*;
import com.rbkmoney.token.keeper.factory.AuthDataFactory;
import com.rbkmoney.token.keeper.mg.repository.AuthDataRepository;
import com.rbkmoney.token.keeper.service.JweTokenGenerator;
import lombok.RequiredArgsConstructor;
import org.apache.thrift.TException;

import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
public class TokenKeeperHandler implements TokenKeeperSrv.Iface {

    private final AuthDataFactory authDataFactory;
    private final JweTokenGenerator<AuthData> jweTokenGenerator;
    private final AuthDataRepository authDataRepository;

    @Override
    public AuthData create(Scope scope, Map<String, String> metadata, String subjectId, String realm) throws TException {
        AuthData authData = authDataFactory.create(scope, metadata, subjectId, realm);
        authDataRepository.save(authData);
        return authData;
    }

    @Override
    public AuthData createWithExpiration(Scope scope, Map<String, String> metadata, String subjectId, String realm,
                                         String expirationTime) throws TException {
        return authDataFactory.create(scope, metadata, subjectId, realm, expirationTime);
    }

    @Override
    public AuthData getByToken(String jwe) throws TException {
        AuthData authData = jweTokenGenerator.decode(jwe);
        if (Strings.isNullOrEmpty(authData.getExpTime())) {
            authData = authDataRepository.get(authData.id);
        } else {
            authData.setToken(jwe);
        }
        return Optional.ofNullable(authData)
                .orElseThrow(AuthDataNotFound::new);
    }

    @Override
    public AuthData get(String tokenId) throws TException {
        return Optional.ofNullable(authDataRepository.get(tokenId))
                .orElseThrow(AuthDataNotFound::new);
    }

    @Override
    public void revoke(String tokenId) throws TException {
        AuthData authData = Optional.ofNullable(authDataRepository.get(tokenId))
                .orElseThrow(AuthDataNotFound::new);
        authData.setStatus(AuthDataStatus.revoked);
        authDataRepository.save(authData);
    }

}
