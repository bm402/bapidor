package com.github.bncrypted.bapidor.ui;

import burp.ITab;
import com.github.bncrypted.bapidor.api.ApiStore;

import javax.swing.*;
import java.awt.*;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class SuiteTab implements ITab {
    
    private final Map<String, ApiStore> apiStores;
    private JTabbedPane tabbedPane;
    private final AtomicInteger tabCounter;
    
    public SuiteTab(Map<String, ApiStore> apiStores) {
        this.apiStores = apiStores;
        tabCounter = new AtomicInteger(0);
    }

    public String getTabCaption() {
        return "bapidor";
    }

    public Component getUiComponent() {
        return createInitialUi();
    }

    private JPanel createInitialUi() {
        // main panels
        JPanel mainPnl = new JPanel();
        JButton addNewTabBtn = new JButton("New tab");
        tabbedPane = new JTabbedPane();

        // first tab
        JPanel tab = new ApiStoreTab(apiStores);
        tabbedPane.addTab(getNextTabId(), null, tab);

        addNewTabBtn.addActionListener(l -> {
            JPanel newTab = new ApiStoreTab(apiStores);
            tabbedPane.addTab(getNextTabId(), null, newTab);
        });

        mainPnl.add(addNewTabBtn);
        mainPnl.add(tabbedPane);
        return mainPnl;
    }

    private String getNextTabId() {
        int id = tabCounter.incrementAndGet();
        return String.valueOf(id);
    }
}
