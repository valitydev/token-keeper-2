package com.rbkmoney.token.keeper.util;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.AuthDataStatus;
import com.rbkmoney.token.keeper.Reference;
import com.rbkmoney.token.keeper.Scope;

import java.util.Date;
import java.util.HashMap;

public class AuthDataUtil {

    public static AuthData createWithoutExpDate(String id) {
        AuthData authData = new AuthData();
        authData.id = id;
        authData.token = "";
        authData.status = AuthDataStatus.active;
        authData.exp_time = new Date().toString();
        authData.scope = createScope();
        authData.metadata = new HashMap<>();
        authData.subject_id = "subject_id";
        authData.realm = "realm";
        return authData;
    }

    public static Scope createScope() {
        Scope scope = new Scope();
        scope.reference = createReference();
        return scope;
    }

    public static Reference createReference() {
        Reference reference = new Reference();
        reference.shop_id = "shop_id";
        reference.party_id = "party_id";
        return reference;
    }

}
