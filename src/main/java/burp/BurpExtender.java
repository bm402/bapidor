package burp;

import com.github.bncrypted.bapidor.listener.HttpListener;
import com.github.bncrypted.bapidor.ui.SuiteTab;

public class BurpExtender implements IBurpExtender {
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("bapidor");
        callbacks.registerHttpListener(new HttpListener(callbacks.getHelpers(), callbacks.getStdout()));
        callbacks.addSuiteTab(new SuiteTab());
    }
}
