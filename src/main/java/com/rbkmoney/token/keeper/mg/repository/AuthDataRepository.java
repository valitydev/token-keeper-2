package com.rbkmoney.token.keeper.mg.repository;

import com.rbkmoney.token.keeper.AuthData;

import java.util.Optional;

/**
 * @author k.struzhkin on 11/21/18
 */
public interface AuthDataRepository {

    void create(AuthData data);

    void update(AuthData data);

    Optional<AuthData> get(String id);

}
