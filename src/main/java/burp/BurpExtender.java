package burp;

import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.listener.HttpListener;
import com.github.bncrypted.bapidor.ui.SuiteTab;

import java.util.HashMap;
import java.util.Map;

public class BurpExtender implements IBurpExtender {
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Map<String, ApiStore> apiStores = new HashMap<>();
        callbacks.setExtensionName("bapidor");
        callbacks.registerHttpListener(new HttpListener(apiStores, callbacks.getHelpers(), callbacks.getStdout()));
        callbacks.addSuiteTab(new SuiteTab(apiStores));
    }
}
