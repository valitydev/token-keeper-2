package com.rbkmoney.token.keeper.factory;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.AuthDataStatus;
import com.rbkmoney.token.keeper.Scope;
import com.rbkmoney.token.keeper.service.JweTokenGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

/**
 * @author k.struzhkin on 11/21/18
 */
@Component
@RequiredArgsConstructor
public class AuthDataFactory {

    private static final String EMPTY_STRING = "";
    private final JweTokenGenerator<AuthData> jweTokenGenerator;

    public AuthData create(Scope scope, Map<String, String> metadata, String subjectId, String realm) {
        return create(scope, metadata, subjectId, realm, EMPTY_STRING);
    }

    public AuthData create(Scope scope, Map<String, String> metadata, String subjectId, String realm, String expirationTime) {
        AuthData authData = new AuthData();
        authData.setId(UUID.randomUUID().toString());
        authData.setRealm(realm);
        authData.setSubjectId(subjectId);
        authData.setMetadata(metadata);
        authData.setScope(scope);
        authData.setStatus(AuthDataStatus.active);
        authData.setExpTime(expirationTime);
        authData.setToken(jweTokenGenerator.generate(authData));
        return authData;
    }

}
