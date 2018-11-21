package com.rbkmoney.token.keeper.mg.repository;

import com.rbkmoney.machinarium.client.AutomatonClient;
import com.rbkmoney.machinarium.domain.TMachineEvent;
import com.rbkmoney.token.keeper.AuthData;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author k.struzhkin on 11/21/18
 */
@Service
@RequiredArgsConstructor
public class AuthDataRepositoryImpl implements AuthDataRepository {

    private final AutomatonClient<AuthData, AuthData> automatonClient;

    @Override
    public void create(AuthData data) {
        automatonClient.start(data.id, data);
    }

    @Override
    public void update(AuthData data) {
        automatonClient.call(data.id, data);
    }

    @Override
    public Optional<AuthData> get(String id) {
        List<TMachineEvent<AuthData>> tMachineEvents = automatonClient.getEvents(id);
        if (tMachineEvents == null || tMachineEvents.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(tMachineEvents.get(tMachineEvents.size() - 1).getData());
    }
}
