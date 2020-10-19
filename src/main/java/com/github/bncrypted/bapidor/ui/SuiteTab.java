package com.github.bncrypted.bapidor.ui;

import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class SuiteTab implements ITab {

    public String getTabCaption() {
        return "bapidor";
    }

    public Component getUiComponent() {
        return createGui();
    }

    private JPanel createGui() {

        // labels
        JLabel baseUriLbl = new JLabel("Base URI:");
        JLabel highPrivilegeTokenLbl = new JLabel("High privilege token:");
        JLabel lowPrivilegeTokenLbl = new JLabel("Low privilege token:");

        // text fields
        JTextField baseUriTf = new JTextField();
        JTextField highPrivilegeTokenTf = new JTextField();
        JTextField lowPrivilegeTokenTf = new JTextField();

        // buttons
        JToggleButton activatedBtn = new JToggleButton("Start");
        JButton saveBtn = new JButton("Save");

        // button functionality
        activatedBtn.addChangeListener(e -> {
            if (activatedBtn.isSelected()) {
                activatedBtn.setText("Stop");
            } else {
                activatedBtn.setText("Start");
            }
        });

        // populate main panel
        JPanel mainPnl = new JPanel();

        GroupLayout layout = new GroupLayout(mainPnl);
        mainPnl.setLayout(layout);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(baseUriLbl)
                                .addComponent(highPrivilegeTokenLbl)
                                .addComponent(lowPrivilegeTokenLbl))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(baseUriTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                                .addComponent(highPrivilegeTokenTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                                .addComponent(lowPrivilegeTokenTf, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(activatedBtn)
                                .addComponent(saveBtn)));

        layout.linkSize(SwingConstants.HORIZONTAL, activatedBtn, saveBtn);


        layout.setVerticalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(baseUriLbl)
                        .addComponent(baseUriTf))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(highPrivilegeTokenLbl)
                        .addComponent(highPrivilegeTokenTf)
                        .addComponent(activatedBtn))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(lowPrivilegeTokenLbl)
                        .addComponent(lowPrivilegeTokenTf)
                        .addComponent(saveBtn)));

        /*GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(10, 10, 10, 10);
        constraints.gridwidth = 400;

        constraints.gridx = 0;
        constraints.gridy = 0;
        mainPnl.add(baseUriLbl, constraints);

        constraints.gridx = 1;
        constraints.gridy = 0;
        mainPnl.add(baseUriTf, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        mainPnl.add(highPrivilegeTokenLbl, constraints);

        constraints.gridx = 1;
        constraints.gridy = 1;
        mainPnl.add(highPrivilegeTokenTf, constraints);

        constraints.gridx = 0;
        constraints.gridy = 2;
        mainPnl.add(lowPrivilegeTokenLbl, constraints);

        constraints.gridx = 1;
        constraints.gridy = 2;
        mainPnl.add(lowPrivilegeTokenTf, constraints);

        constraints.gridx = 0;
        constraints.gridy = 3;
        mainPnl.add(activatedBtn, constraints);

        constraints.gridx = 1;
        constraints.gridy = 3;
        mainPnl.add(saveBtn, constraints);*/

        return mainPnl;
    }
}
