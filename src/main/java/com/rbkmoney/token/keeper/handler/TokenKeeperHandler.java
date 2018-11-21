package com.rbkmoney.token.keeper.handler;

import com.google.common.base.Strings;
import com.rbkmoney.token.keeper.*;
import com.rbkmoney.token.keeper.factory.AuthDataFactory;
import com.rbkmoney.token.keeper.mg.repository.AuthDataRepository;
import com.rbkmoney.token.keeper.service.JweTokenGenerator;
import lombok.RequiredArgsConstructor;
import org.apache.thrift.TException;

import java.util.Map;

/**
 * @author k.struzhkin on 11/21/18
 */
@RequiredArgsConstructor
public class TokenKeeperHandler implements TokenKeeperSrv.Iface {

    private final AuthDataFactory authDataFactory;
    private final JweTokenGenerator<AuthData> jweTokenGenerator;
    private final AuthDataRepository authDataRepository;

    @Override
    public AuthData create(Scope scope, Map<String, String> metadata, String subjectId, String realm) throws TException {
        AuthData authData = authDataFactory.create(scope, metadata, subjectId, realm);
        authDataRepository.create(authData);
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
            return authDataRepository.get(authData.id)
                    .orElseThrow(AuthDataNotFound::new);
        }
        authData.setToken(jwe);
        return authData;
    }

    @Override
    public AuthData get(String tokenId) throws TException {
        return authDataRepository.get(tokenId)
                .orElseThrow(AuthDataNotFound::new);
    }

    @Override
    public void revoke(String tokenId) throws TException {
        AuthData authData = authDataRepository.get(tokenId)
                .orElseThrow(AuthDataNotFound::new);
        authData.setStatus(AuthDataStatus.revoked);
        authDataRepository.update(authData);
    }

}
