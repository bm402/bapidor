package burp;

import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.listener.HttpListener;
import com.github.bncrypted.bapidor.ui.SuiteTab;

public class BurpExtender implements IBurpExtender {
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        ApiStore apiStore = new ApiStore();
        apiStore.setStdout(callbacks.getStdout());
        callbacks.setExtensionName("bapidor");
        callbacks.registerHttpListener(new HttpListener(apiStore, callbacks.getHelpers(), callbacks.getStdout()));
        callbacks.addSuiteTab(new SuiteTab(apiStore));
    }
}
