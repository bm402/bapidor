package com.github.bncrypted.bapidor.ui;

import burp.ITab;
import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.AuthDetails;

import javax.swing.*;
import java.awt.*;

public class SuiteTab implements ITab {
    
    private final ApiStore apiStore;
    
    public SuiteTab(ApiStore apiStore) {
        this.apiStore = apiStore;
    }

    public String getTabCaption() {
        return "bapidor";
    }

    public Component getUiComponent() {
        return createGui();
    }

    private JPanel createGui() {

        // labels
        JLabel baseUriLbl = new JLabel("Base URI:");
        JLabel authHeaderNameLbl = new JLabel("Auth header name:");
        JLabel authHeaderValuePrefixLbl = new JLabel("Auth header value prefix:");
        JLabel highPrivilegeTokenLbl = new JLabel("High privilege token:");
        JLabel lowPrivilegeTokenLbl = new JLabel("Low privilege token:");

        // text fields
        JTextField baseUriTf = new JTextField();
        JTextField authHeaderNameTf = new JTextField();
        JTextField authHeaderValuePrefixTf = new JTextField();
        JTextField highPrivilegeTokenTf = new JTextField();
        JTextField lowPrivilegeTokenTf = new JTextField();

        // buttons
        JToggleButton activatedBtn = new JToggleButton("Start");
        JButton saveBtn = new JButton("Save");
        JToggleButton resetBtn = new JToggleButton("Reset");

        // button functionality
        activatedBtn.addChangeListener(e -> {
            if (activatedBtn.isSelected()) {
                activatedBtn.setText("Stop");
                apiStore.setBaseUri(baseUriTf.getText());
                AuthDetails authDetails = AuthDetails.builder()
                        .headerName(authHeaderNameTf.getText())
                        .headerValuePrefix(authHeaderValuePrefixTf.getText())
                        .highPrivilegedToken(highPrivilegeTokenTf.getText())
                        .lowPrivilegedToken(lowPrivilegeTokenTf.getText())
                        .build();
                apiStore.setAuthDetails(authDetails);
                apiStore.setListening(true);
            } else {
                activatedBtn.setText("Start");
                apiStore.setListening(false);
            }
        });

        resetBtn.addChangeListener(e -> {
            if (resetBtn.isSelected()) {
                resetBtn.setText("Are you sure?");
            } else {
                resetBtn.setText("Reset");
                activatedBtn.setSelected(false);
                apiStore.reset();
            }
        });

        // populate main panel
        JPanel mainPnl = new JPanel();

        GroupLayout layout = new GroupLayout(mainPnl);
        mainPnl.setLayout(layout);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(baseUriLbl)
                                .addComponent(authHeaderNameLbl)
                                .addComponent(authHeaderValuePrefixLbl)
                                .addComponent(highPrivilegeTokenLbl)
                                .addComponent(lowPrivilegeTokenLbl))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(baseUriTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                                .addComponent(authHeaderNameTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                                .addComponent(authHeaderValuePrefixTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                                .addComponent(highPrivilegeTokenTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                                .addComponent(lowPrivilegeTokenTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(activatedBtn)
                                .addComponent(saveBtn)
                                .addComponent(resetBtn)));

        layout.linkSize(SwingConstants.HORIZONTAL, activatedBtn, saveBtn, resetBtn);

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(baseUriLbl)
                        .addComponent(baseUriTf)
                        .addComponent(activatedBtn))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(authHeaderNameLbl)
                        .addComponent(authHeaderNameTf)
                        .addComponent(saveBtn))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(authHeaderValuePrefixLbl)
                        .addComponent(authHeaderValuePrefixTf))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(highPrivilegeTokenLbl)
                        .addComponent(highPrivilegeTokenTf))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(lowPrivilegeTokenLbl)
                        .addComponent(lowPrivilegeTokenTf)
                        .addComponent(resetBtn)));

        return mainPnl;
    }
}
