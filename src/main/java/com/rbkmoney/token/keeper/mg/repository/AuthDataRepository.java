package com.rbkmoney.token.keeper.mg.repository;

import com.rbkmoney.token.keeper.AuthData;

import java.util.Optional;

public interface AuthDataRepository {

    void create(AuthData data);

    void update(AuthData data);

    Optional<AuthData> get(String id);

}
