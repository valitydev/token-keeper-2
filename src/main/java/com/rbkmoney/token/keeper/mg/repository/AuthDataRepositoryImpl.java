package com.rbkmoney.token.keeper.mg.repository;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.AuthDataNotFound;
import org.springframework.stereotype.Service;

@Service
public class AuthDataRepositoryImpl implements AuthDataRepository {

    @Override
    public void save(AuthData data) {
        //TODO mg invocation
    }

    @Override
    public AuthData get(String id) throws AuthDataNotFound {
        //TODO mg invocation
        return null;
    }
}
