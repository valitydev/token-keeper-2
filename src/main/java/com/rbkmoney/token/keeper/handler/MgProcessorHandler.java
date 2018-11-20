package com.rbkmoney.token.keeper.handler;

import com.rbkmoney.machinarium.domain.CallResultData;
import com.rbkmoney.machinarium.domain.SignalResultData;
import com.rbkmoney.machinarium.domain.TMachineEvent;
import com.rbkmoney.machinarium.handler.AbstractProcessorHandler;
import com.rbkmoney.machinegun.stateproc.ComplexAction;
import com.rbkmoney.token.keeper.AuthData;

import java.util.Collections;
import java.util.List;


public class MgProcessorHandler extends AbstractProcessorHandler<AuthData, AuthData> {

    public MgProcessorHandler(Class<AuthData> argsType, Class<AuthData> resultType) {
        super(argsType, resultType);
    }

    @Override
    protected SignalResultData<AuthData> processSignalInit(String s, String s1, AuthData authData) {
        return new SignalResultData<>(Collections.singletonList(authData), new ComplexAction());
    }

    @Override
    protected SignalResultData<AuthData> processSignalTimeout(String s, String s1, List<TMachineEvent<AuthData>> list) {
        //not use in this service
        return null;
    }

    @Override
    protected CallResultData<AuthData> processCall(String s, String s1, AuthData authData, List<TMachineEvent<AuthData>> list) {
        return new CallResultData<>(authData, Collections.singletonList(authData), new ComplexAction());
    }

}
