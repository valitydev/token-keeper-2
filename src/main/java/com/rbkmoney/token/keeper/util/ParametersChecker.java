package com.rbkmoney.token.keeper.util;

import com.google.common.base.Strings;
import org.apache.thrift.TException;

public class ParametersChecker {

    public static void checkBadParameters(String tokenId, String s) throws TException {
        if (Strings.isNullOrEmpty(tokenId)) {
            throw new TException(s);
        }
    }

}
