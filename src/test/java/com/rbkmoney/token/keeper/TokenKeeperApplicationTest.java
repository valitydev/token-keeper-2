package com.rbkmoney.token.keeper;

import com.google.common.base.Strings;
import com.rbkmoney.token.keeper.mg.repository.AuthDataRepository;
import com.rbkmoney.token.keeper.util.AuthDataUtil;
import com.rbkmoney.woody.thrift.impl.http.THClientBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.thrift.TException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;

import java.net.URI;
import java.util.HashMap;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class TokenKeeperApplicationTest {

    private static final String TEST_SUBJECT_ID = "test_subjectId";
    private static final String TEST_REALM = "test_realm";
    private static final String EXP_TIME = "exp_time";
    private static final String TEST_ID = "test_id";

    private static final String TEST_TOKEN = "eyJlbmMiOiJBMjU2R0NNIiwidGFnIjoicUh3VzB4cEQ2c3RlSjVWdElZeGJWZyIsImFsZyI6Ik" +
            "EyNTZHQ01LVyIsIml2IjoiOC13akMwM3IwVGlhbXhZQyJ9.WSs5q6_tY0T4yDPGfkLZRN0mk_-Y28ppw4LaSrHXzz8.5WX6QI_tIZlpy4Nx" +
            ".Wqen0mIpyONNA_xAzJ_BYtc4BSomfPys2QDAUUiFDG8CFhHTSXKdF__ltN7l_Wim1Hf7k_YtNdL9lNTzmdyzwDszbPYmkMPp71EiNVoPD0" +
            "84jRozC5KerBqUaN_NIaSPzlvSCcrTONQpmMOqtckZV3G1XNHKbmw_uaQgws_snLGFhE4x8xCFpuwda6spAmUZrvQ8bnEi4zSMxHuHtDlMd" +
            "PrPcrJpi0DLDWhKHndTQaZC-xPe09FAR8NluP09xcPQDmxYnMGDNcVTNBe6XE507fwe7M32EH4Zk_Gv2B4zaPx4I3PzwrhhO1BfyD0hiwnC" +
            "LClZEcOynXaETodqnTHmlHA.GoaqbADnIY4HNQmonEVXaQ";

    private static final String TEST_TOKEN_WITH_EXP = "eyJlbmMiOiJBMjU2R0NNIiwidGFnIjoiRWJ1X3lQSEFzRDJnSjdqUFF4UE9CUSIsImFsZyI6Ik" +
            "EyNTZHQ01LVyIsIml2IjoiVVdSS3ZUeU1oX2VkTFYxWCJ9.d7ihF4wB8CJzevQW97ISQyVGOnD-oQkBMN4vSFKtfJQ.6KnfZx_H7eLB_Lhq" +
            ".w-zc4o7BjI71VMX92LiK4c3eYD_vKPm1fci6R9oq0Pgf8iRpVdekVhpb2FUqS8kjQGCFJ9JyDwCeJqB92j0eY_XyVOl_o-xAsfjV-a-F1V" +
            "X3mDjWIbi8fEviHOiq5YqOq0iCsqZBpiY3n0_jTUmS8U1UmqXyIBXJmL6lT8gq1Pe78H9K2FQU6WpOxYZt31PVWbsmEadjdIe6S6zR-fV3I" +
            "yFdDTzCpK8jeGwxT_10g4ZtEzzSHPBec1ghnqSqJtCwvB8qyqPymioBe_HCDW2aplf0IfoqPGd2FSrLGvGjlda71XQGLU_HgHxLvZQE9Kgu" +
            "t2pI1sGTq8DPAOpLG8b-njYF3v11VdLxHw.hE8CBMXy7WyvOzeL1L-bmA";

    public static final String TEST_TOKEN_ID_NEW = "72af7c4b-937a-4e3f-976b-4d9ba7a1a0d8";
    public static final String TEST_TOKEN_ID_NEW_2 = "43c054ea-d5b7-4077-8a63-66573703f80c";

    private TokenKeeperSrv.Iface client;

    AuthData AUTH_DATA = AuthDataUtil.createWithoutExpDate(TEST_ID);
    @Captor
    ArgumentCaptor<AuthData> authDataCaptor;

    @LocalServerPort
    int serverPort;

    private static String SERVICE_URL = "http://localhost:%s/token_keeper";

    @MockBean
    private AuthDataRepository authDataRepository;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        THClientBuilder clientBuilder = new THClientBuilder()
                .withAddress(new URI(getServiceUrl()));
        client = clientBuilder.build(TokenKeeperSrv.Iface.class);
        when(authDataRepository.get(TEST_ID)).thenReturn(AUTH_DATA);
        doNothing().when(authDataRepository).save(any());
    }

    @Test
    // Common test for only one start servlet
    public void commonTest() throws TException {
        Scope scope = AuthDataUtil.createScope();

        createTest(scope);

        createWithExpirationTest(scope);

        getTest();

        getByTokenTest();

        revokeTest();

    }

    private void revokeTest() throws TException {
        reset(authDataRepository);
        when(authDataRepository.get(any())).thenReturn(AUTH_DATA);
        client.revoke(TEST_ID);
        verify(authDataRepository).save(authDataCaptor.capture());
        assertEquals(AuthDataStatus.revoked, authDataCaptor.getValue().status);
    }

    private void createTest(Scope scope) throws TException {
        AuthData authData = client.create(scope, new HashMap<>(), TEST_SUBJECT_ID, TEST_REALM);
        assertCommonAuthData(authData);
        assertTrue(Strings.isNullOrEmpty(authData.exp_time));
        verify(authDataRepository, times(1)).save(any());
    }

    private void createWithExpirationTest(Scope scope) throws TException {
        AuthData authData = client.createWithExpiration(scope, new HashMap<>(), TEST_SUBJECT_ID, TEST_REALM, EXP_TIME);
        assertCommonAuthData(authData);
        assertEquals(EXP_TIME, authData.exp_time);
    }

    private void getTest() throws TException {
        AuthData authData = client.get(TEST_ID);
        assertEquals(TEST_ID, authData.id);
    }

    private void getByTokenTest() throws TException {
        AuthData authData = client.getByToken(TEST_TOKEN_WITH_EXP);
        assertEquals(TEST_TOKEN_ID_NEW, authData.id);

        when(authDataRepository.get(TEST_TOKEN_ID_NEW_2)).thenReturn(AUTH_DATA);
        authData = client.getByToken(TEST_TOKEN);
        verify(authDataRepository, times(1)).get(TEST_TOKEN_ID_NEW_2);
        assertEquals(TEST_ID, authData.id);
    }

    private void assertCommonAuthData(AuthData authData) {
        assertEquals(TEST_SUBJECT_ID, authData.subject_id);
        assertEquals(TEST_REALM, authData.realm);
        assertFalse(Strings.isNullOrEmpty(authData.id));
        assertFalse(Strings.isNullOrEmpty(authData.token));
    }

    String getServiceUrl() {
        return String.format(SERVICE_URL, serverPort);
    }
}
