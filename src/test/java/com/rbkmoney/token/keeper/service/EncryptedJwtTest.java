package com.rbkmoney.token.keeper.service;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.util.AuthDataUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;

@Slf4j
public class EncryptedJwtTest {

    public static final String TEST = "test";
    private JweTokenGenerator<AuthData> jwtTokenGenerator = new JweTokenGeneratorImpl("2C+kMbFi7DrV0wsIR0KQ81RbkylqMOdqNNHV1loJ4Bg=");

    @Test
    public void testEncrypt() {
        AuthData withoutExpDate = AuthDataUtil.createWithoutExpDate(TEST);
        String jwe = jwtTokenGenerator.generate(withoutExpDate);
        AuthData decode = jwtTokenGenerator.decode(jwe);
        Assert.assertEquals(TEST, decode.id);
    }

}