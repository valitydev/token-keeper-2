package com.rbkmoney.token.keeper.service;

/**
 * @author k.struzhkin on 11/21/18
 */
public interface JweTokenGenerator<T> {

    String generate(T scope);

    T decode(String jwt);

}
