package com.rbkmoney.token.keeper.factory;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.Scope;
import com.rbkmoney.token.keeper.service.JweTokenGenerator;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

public class AuthDataFactoryTest {

    public static final String TEST_TOKEN = "test-token";
    public static final String REALM = "realm";
    public static final String SUBJECT_ID = "subject_id";
    public static final String TEST_DATE = "test_date";
    public static final String EMPTY_STRING = "";

    @Mock
    JweTokenGenerator<AuthData> jweTokenGenerator;
    AuthDataFactory authDataFActory;

    @Before
    public void init(){
        MockitoAnnotations.initMocks(this);
        when(jweTokenGenerator.generate(any())).thenReturn(TEST_TOKEN);
        authDataFActory = new AuthDataFactory(jweTokenGenerator);
    }

    @Test
    public void mapTo() {
        Scope scope = new Scope();
        AuthData authData = authDataFActory.create(scope, new HashMap<>(), SUBJECT_ID, REALM);

        assertEquals(TEST_TOKEN, authData.token);
        assertEquals(SUBJECT_ID, authData.subject_id);
        assertEquals(REALM, authData.realm);
        assertEquals(EMPTY_STRING, authData.exp_time);
    }

    @Test
    public void mapToWithExpDate() {
        Scope scope = new Scope();
        AuthData authData = authDataFActory.create(scope, new HashMap<>(), SUBJECT_ID, REALM, TEST_DATE);

        assertEquals(TEST_DATE, authData.exp_time);
    }
}