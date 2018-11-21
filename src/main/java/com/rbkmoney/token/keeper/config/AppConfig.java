package com.rbkmoney.token.keeper.config;

import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.TokenKeeperSrv;
import com.rbkmoney.token.keeper.factory.AuthDataFactory;
import com.rbkmoney.token.keeper.handler.TokenKeeperWithErrorHandler;
import com.rbkmoney.token.keeper.mg.repository.AuthDataRepository;
import com.rbkmoney.token.keeper.service.JweTokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author k.struzhkin on 11/21/18
 */
@Configuration
public class AppConfig {

    @Bean
    @Autowired
    public TokenKeeperSrv.Iface requestHandler(AuthDataFactory authDataFActory, JweTokenGenerator<AuthData> jweTokenGenerator,
                                               AuthDataRepository authDataRepository) {
        return new TokenKeeperWithErrorHandler(authDataFActory, jweTokenGenerator, authDataRepository);
    }

}
