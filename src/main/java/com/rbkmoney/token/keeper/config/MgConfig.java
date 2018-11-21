package com.rbkmoney.token.keeper.config;

import com.rbkmoney.machinarium.client.AutomatonClient;
import com.rbkmoney.machinarium.client.TBaseAutomatonClient;
import com.rbkmoney.machinegun.stateproc.AutomatonSrv;
import com.rbkmoney.machinegun.stateproc.ProcessorSrv;
import com.rbkmoney.token.keeper.AuthData;
import com.rbkmoney.token.keeper.handler.MgProcessorHandler;
import com.rbkmoney.woody.thrift.impl.http.THSpawnClientBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;

/**
 * @author k.struzhkin on 11/21/18
 */
@Configuration
public class MgConfig {

    @Value("${mg.service.url}")
    Resource resource;

    @Value("${mg.service.namespace}")
    String namespace;

    @Bean
    public AutomatonSrv.Iface automationSrvIface() {
        try {
            return new THSpawnClientBuilder().withAddress(resource.getURI()).build(AutomatonSrv.Iface.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Bean
    @Autowired
    public AutomatonClient<AuthData, AuthData> automatonClient(AutomatonSrv.Iface automationSrvIface) {
        return new TBaseAutomatonClient<>(automationSrvIface, namespace, AuthData.class);
    }

    @Bean
    public ProcessorSrv.Iface mgProcessorHandler() {
        return new MgProcessorHandler(AuthData.class, AuthData.class);
    }
}
