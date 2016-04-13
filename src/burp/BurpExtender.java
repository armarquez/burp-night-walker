/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Antonio Marquez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package burp;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;

/**
 * Burp extension to redirect all requests after a specified epoch time
 */
public class BurpExtender implements IBurpExtender, IHttpListener {
	static final String NAME = "Night Walker";

	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private IBurpExtenderCallbacks callbacks;

	//settings
	private int stopTime;
	private String redirectUrl;

	//is the extension enabled?
	private boolean isEnabled = false;

    //for logging
    private int dropCount = 0;

	//text fields for the GUI
	private JTextField timeTextField = new JTextField("", 10); // With size and default text
	private JTextField redirectTextField = new JTextField("nowayinhellisthisanactualdomain.com"); // With size and default text
	private JToggleButton toggleOnOff = new JToggleButton(isEnabled ? "DISABLE" : "ENABLE");
	private JLabel statusLabel = new JLabel();
	private JTabbedPane tabbedPane = new JTabbedPane();

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// set our extension name
		callbacks.setExtensionName(NAME);

		// printing to Burp's standard out
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = new PrintWriter(callbacks.getStderr(), true);

		// obtain an extension helpers object
		this.helpers = callbacks.getHelpers();

		// register ourselves as a Http Listener
		this.callbacks.registerHttpListener(this);

		initializeGUI();
		this.stdout.println("Loaded Night Walker Extension");
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest && this.isEnabled) {
            IRequestInfo requestInfo = this.helpers.analyzeRequest(messageInfo);
			int currentTime = (int) (System.currentTimeMillis() / 1000L);
            if (currentTime >= this.stopTime) {
				// get the HTTP service for the request
				IHttpService httpService = messageInfo.getHttpService();

				messageInfo.setHttpService(this.helpers.buildHttpService(
						this.redirectUrl, httpService.getPort(), httpService.getProtocol()));

				this.stdout.println("DROPPING REQUEST");
                if (dropCount < 20) {
                    System.out.printf("** DROP REQUEST DISPLAY COUNT (%s/20) **\n%s",
                            dropCount+1, this.helpers.bytesToString(messageInfo.getRequest()));
                }
                dropCount++;
			}
		}
	}

	class StartHttpListener implements ActionListener {

		public StartHttpListener() {
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			//toggle status
			isEnabled = !isEnabled;

			JToggleButton button = (JToggleButton) e.getSource();

			if (isEnabled) {
                timeTextField.setText(timeTextField.getText().trim());
                redirectTextField.setText(redirectTextField.getText().trim());
                try {
                    stopTime = Integer.parseInt(timeTextField.getText());
                } catch (NumberFormatException ex) {
                    stopTime = 0;
                    timeTextField.setText("0");
                }
                redirectUrl = redirectTextField.getText();

                redirectTextField.setEditable(false);
                timeTextField.setEditable(false);
				button.setText("DISABLED");
			} else {
                dropCount = 0;
                redirectTextField.setEditable(true);
                timeTextField.setEditable(true);
				button.setText("ENABLED");
			}
		}
	}


	public static void main(String[] args) {
		BurpExtender be = new BurpExtender();
		be.initializeGUI();
	}

	private void initializeGUI() throws HeadlessException {
		JPanel outputPanel = new JPanel();
		outputPanel.setLayout(new BorderLayout());

		//setup the on/off button
		this.toggleOnOff.setSelected(this.isEnabled);
		this.toggleOnOff.addActionListener(new StartHttpListener());

		//sub panel containing auto-sign controls
		GridLayout grid = new GridLayout(5, 2);
		grid.setHgap(4);

		JPanel parameterPanel = new JPanel(grid);
		parameterPanel.setName("Redirect All Traffic");
		parameterPanel.setBorder(new TitledBorder("Parameters"));

		parameterPanel.add(new JLabel("Stop testing at:"), 0);
		parameterPanel.add(this.timeTextField, 1);

		parameterPanel.add(new JLabel("Redirection URL:"), 2);
		parameterPanel.add(this.redirectTextField, 3);

		//tabs within control panel window
		this.tabbedPane.addTab("Settings", parameterPanel);

		//start button and overall status
		JPanel bottomPanel = new JPanel(new GridLayout(1,2));
		bottomPanel.add(this.statusLabel, 0);
		bottomPanel.add(this.toggleOnOff, 1);

		//the whole GUI window
		JFrame gui = new JFrame("Redirect All Traffic");
		gui.setLayout(new BorderLayout());
		gui.add(this.tabbedPane, BorderLayout.CENTER);
		gui.add(bottomPanel, BorderLayout.SOUTH);
		if (this.callbacks != null) this.callbacks.customizeUiComponent(gui);  //apply Burp's styles
		gui.pack();
		gui.setVisible(true);
	}
}
