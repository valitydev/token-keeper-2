package com.rbkmoney.token.keeper.handler;

import com.rbkmoney.machinarium.domain.CallResultData;
import com.rbkmoney.machinarium.domain.SignalResultData;
import com.rbkmoney.machinarium.domain.TMachineEvent;
import com.rbkmoney.machinarium.handler.AbstractProcessorHandler;
import com.rbkmoney.machinegun.stateproc.ComplexAction;
import com.rbkmoney.token.keeper.AuthData;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.List;

@Slf4j
public class MgProcessorHandler extends AbstractProcessorHandler<AuthData, AuthData> {

    public MgProcessorHandler(Class<AuthData> argsType, Class<AuthData> resultType) {
        super(argsType, resultType);
    }

    @Override
    protected SignalResultData<AuthData> processSignalInit(String namespace, String machineId, AuthData authData) {
        log.info("Request processSignalInit() namespace: {} machineId: {} authData: {}", namespace, machineId, authData);
        SignalResultData<AuthData> authDataSignalResultData = new SignalResultData<>(Collections.singletonList(authData), new ComplexAction());
        log.info("Response: {}", authDataSignalResultData);
        return authDataSignalResultData;
    }

    @Override
    protected SignalResultData<AuthData> processSignalTimeout(String namespace, String machineId, List<TMachineEvent<AuthData>> list) {
        log.info("Request processSignalTimeout() namespace: {} machineId: {} list: {}", namespace, machineId, list);
        SignalResultData<AuthData> authDataSignalResultData = new SignalResultData<>(Collections.emptyList(), new ComplexAction());
        log.info("Response: {}", authDataSignalResultData);
        return authDataSignalResultData;
    }

    @Override
    protected CallResultData<AuthData> processCall(String namespace, String machineId, AuthData authData, List<TMachineEvent<AuthData>> list) {
        log.info("Request processCall() namespace: {} machineId: {} list: {}", namespace, machineId, list);
        CallResultData<AuthData> callResultData = new CallResultData<>(authData, Collections.singletonList(authData), new ComplexAction());
        log.info("Response: {}", callResultData);
        return callResultData;
    }

}
