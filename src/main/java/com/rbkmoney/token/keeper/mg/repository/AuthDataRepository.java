package com.rbkmoney.token.keeper.mg.repository;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.AuthDataNotFound;

public interface AuthDataRepository {

    void save(AuthData data);

    AuthData get(String id) throws AuthDataNotFound;

}
