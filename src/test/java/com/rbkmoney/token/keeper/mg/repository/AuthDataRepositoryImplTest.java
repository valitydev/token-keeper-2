package com.rbkmoney.token.keeper.mg.repository;

import com.rbkmoney.machinarium.client.AutomatonClient;
import com.rbkmoney.machinarium.domain.TMachineEvent;
import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.AuthDataNotFound;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class AuthDataRepositoryImplTest {

    public static final String TEST = "test";
    @Mock
    private AutomatonClient<AuthData, AuthData> automatonClient;

    AuthDataRepositoryImpl authDataRepository;

    @Before
    public void init(){
        MockitoAnnotations.initMocks(this);

        authDataRepository = new AuthDataRepositoryImpl(automatonClient);
    }

    @Test
    public void get() throws AuthDataNotFound {
        ArrayList<TMachineEvent<AuthData>> eventList = new ArrayList<>();
        when(automatonClient.getEvents(TEST)).thenReturn(eventList);
        Optional<AuthData> authDataResult = authDataRepository.get(TEST);
        assertFalse(authDataResult.isPresent());

        AuthData authData = new AuthData();
        eventList.add(new TMachineEvent<>(1, Instant.MAX, authData));
        when(automatonClient.getEvents(TEST)).thenReturn(eventList);
        authDataResult = authDataRepository.get(TEST);
        assertTrue(authDataResult.isPresent());
    }
}