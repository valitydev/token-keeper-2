package com.rbkmoney.token.keeper.service;

public interface JweTokenGenerator<T> {

    String generate(T scope);

    T decode(String jwt);

}
