package com.rbkmoney.token.keeper.resource;

import com.rbkmoney.machinegun.stateproc.ProcessorSrv;
import com.rbkmoney.woody.thrift.impl.http.THServiceBuilder;
import lombok.RequiredArgsConstructor;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import java.io.IOException;

@WebServlet("/mg_processor")
@RequiredArgsConstructor
public class MgProcessorServlet extends GenericServlet {

    private Servlet thriftServlet;

    private final ProcessorSrv.Iface mgProcessorHandler;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        thriftServlet = new THServiceBuilder()
                .build(ProcessorSrv.Iface.class, mgProcessorHandler);
    }

    @Override
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        thriftServlet.service(req, res);
    }
}
