#!/usr/bin/env python3

_AUTH_ = 'RWG' # 02192022

'''
-> EDR Killswitch
-> Graphical utility that allows an analyst or administrator to:
    -> Isolate a single host
    -> Unisolate a single host
    -> Isolate all of the hosts in a given organization
    -> Unisolate all of the hosts in a given organization
'''

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    import requests
    import time
    import sys
except Exception as e:
    print("[!] Library import error: %s " % e)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

'''
Class for the primary graphical user interface
'''

class Window(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        QLabel.__init__(self)
        #
        self.setWindowTitle('EDR Killswitch')
        self.setGeometry(800,100,500,800)
        #
        self.api_key_label   = QLabel("API Key")                                    # Label:       API Key text input field
        self.api_key         = QLineEdit()                                          # Input:       API Key input field / text box
        self.api_key.setPlaceholderText("<API key goes here>")                      # Placeholder: Text for the API Key input field
        self.tenant_label    = QLabel("Tenant FQDN/IP")                             # Label:       Supervisor/Manager Input Field
        self.tenant_addr     = QLineEdit()                                          # Input:       IP/FQDN Field
        self.tenant_addr.setPlaceholderText("<Supervisor FQDN or IP goes here>")    # Placeholder: IP/FQDN placeholder
        self.set_params_btn  = QPushButton("Set Parameters")                        # Button:      Embed API call parameters
        self.clr_params_btn  = QPushButton("Clear Parameters")                      # Button:      Reset the parameter input fields
        self.org_box_label   = QLabel("Select the organization")                    # Label:       Organization combo box label
        self.org_combo_box   = QComboBox()                                          # ComboBox:    Organization combo box
        self.ctr_box_label   = QLabel("Select the collector")                       # Label:       Label for the collector combination 
        self.ctr_combo_box   = QComboBox()                                          # ComboBox:    The collector combination box
        self.isolate_ctr_btn = QPushButton("Isolate Single Host")                   # Button:      Isolate a single collector
        self.isolate_org_btn = QPushButton("Isolate Entire Organization")           # Button:      Isolate en entire organization
        self.restore_ctr_btn = QPushButton("Restore Single Host")                   # Button:      Restore a single collector
        self.restore_org_btn = QPushButton("Restore Entire Organization")           # Button:      Restore an entire organization
        self.output_window   = QPlainTextEdit("")                                   # Button:      Isolate an entire organization
        self.isolate_ctr_btn.setStyleSheet('background-color : red')                # Style:       Red for danger - Single Collector Isolation Button
        self.isolate_org_btn.setStyleSheet('background-color : red')                # Style:       Red for danger - Entire Organization Isolation Button
        self.restore_ctr_btn.setStyleSheet('background-color : blue')               # Style:       Blue for generally accepted positive status indicator - Restore Single Collector (Unisolate) 
        self.restore_org_btn.setStyleSheet('background-color : blue')               # Style:       Blue for generally accepted positive status indicator - Restore the entire organization (Unisolate)
        self.output_window.resize(200,400)                                          # TextField:   Substitute for STDOUT
        #
        '''
        Button Actions
        '''
        #
        self.set_params_btn.clicked.connect(self.SetParams)                         # Button Click Event Handler -> Set the API parameters & test validity 
        self.clr_params_btn.clicked.connect(self.ClearParams)                       # Button Click Event Handler -> Clear the API parameter fields
        self.org_combo_box.currentIndexChanged.connect(self.RegisterOrganization)   # Combo Box Event Handler    -> Set the organization that is to be managed 
        self.isolate_ctr_btn.clicked.connect(self.IsolateHost)                      # Button Click Event Handler -> Isolate a single host - calls function IsolateHost()
        self.restore_ctr_btn.clicked.connect(self.RestoreHost)                      # Button Click Event Handler -> Restore a single host - calls function RestoreHost()
        self.isolate_org_btn.clicked.connect(self.IsolateOrganization)              # Button Click Event Handler -> Isolate all collectors in an organization - IsolateOrganization()
        self.restore_org_btn.clicked.connect(self.RestoreOrganization)              # Button Click Event Handler -> Restore all isolated collectors in an organization - RestoreOrganization()
        #
        '''
        Form layout configuration
        '''
        #
        main_form_layout                 = QFormLayout()                            # Layout: This is the main form layout
        main_form_layout.setVerticalSpacing(10)                                     # Layout: Set the form layout vertical spacing to 10 mystery units
        self.horizontal_param_button_box = QHBoxLayout()                            # Layout: Horizontal - Contains the parameter fields
        self.vertical_org_menu_box       = QVBoxLayout()                            # Layout: Vertical   - Contains the organization combination box
        self.vertical_collector_box      = QVBoxLayout()                            # Layout: Vertical   - Contains the collector combination box
        self.isolate_btn_box             = QHBoxLayout()                            # Layout: Horizontal - Contains the isolation buttons
        self.restore_btn_box             = QHBoxLayout()                            # Layout: Horizontal - Contains the restoration buttons
        self.vertical_feedback_box       = QVBoxLayout()                            # Layout: Vertical   - Contains the vertical text field for output
        #
        self.horizontal_param_button_box.addWidget(self.set_params_btn)             # Widget: Instantiate the set parameters button 
        self.horizontal_param_button_box.addWidget(self.clr_params_btn)             # Widget: Instantiate the clear parameters button
        #
        self.vertical_org_menu_box.addWidget(self.org_box_label)                    # Label:  Organization combination box label
        self.vertical_org_menu_box.addWidget(self.org_combo_box)                    # Widget: Instantiate the organization combination box widget
        #
        self.vertical_collector_box.addWidget(self.ctr_box_label)                   # Label:  Collector combination box label
        self.vertical_collector_box.addWidget(self.ctr_combo_box)                   # Widget: Collector combination box widget
        #
        self.isolate_btn_box.addWidget(self.isolate_ctr_btn)                        # Widget: Instantiate the single collector isolation button
        self.isolate_btn_box.addWidget(self.isolate_org_btn)                        # Widget: Instantiate the organization isolation button
        self.restore_btn_box.addWidget(self.restore_ctr_btn)                        # Widget: Instantiate the single collector restoration button
        self.restore_btn_box.addWidget(self.restore_org_btn)                        # Widget: Instantiate the entire organization restoration button
        #
        self.vertical_feedback_box.addWidget(self.output_window)                    # Widget: Instantiate the vertical text box field
        #
        main_form_layout.addRow(self.tenant_label,self.tenant_addr)                 # Layout: Add the label for the manager input field to the main form
        main_form_layout.addRow(self.api_key_label,self.api_key)                    # Layout: Add the label for the API input field to the main form
        main_form_layout.addRow(self.horizontal_param_button_box)                   # Layout: Integrate the set parameter button and supporting subordinate layout into the main form
        main_form_layout.addRow(self.vertical_org_menu_box)                         # Layout: Add the organization combination box and supporting subordinate layout into the main form
        main_form_layout.addRow(self.vertical_collector_box)                        # Layout: Add the collector selection combination box and the supporting subordinate layout to the main form
        main_form_layout.addRow(self.isolate_btn_box)                               # Layout: Add the isolation buttons and their subordinate layout to the main form
        main_form_layout.addRow(self.restore_btn_box)                               # Layout: Add the restoration buttons and their subordinate layout to the main form
        main_form_layout.addRow(self.vertical_feedback_box)                         # Layout: Add the vertical text field layout to the main form
        #
        self.setLayout(main_form_layout)                                            # Layout: Establish the main form within the main window

    '''
    Input:      str() -> Manager IP Address/FQDN ; str() -> API Key 
    Processing: HTTP Get request to the management endpoint to establish credential validity
    Output:     JSON encoded list of organizations within the EDR Tenant
    '''
    def TestParams(self):
        timestamp = time.ctime()
        try:
            test_url           = "https://{0}/management-rest/organizations/list-organizations".format(self.mgr_address.text())
            self.output_window.insertPlainText("[{0}] Test URL: {1}\n".format(timestamp,test_url))
            headers            = {'X-Auth-Token': '{0}'.format(self.api_key.text())}
            response           = requests.get(test_url, headers=headers, timeout=3, verify=False)
            result             = response.status_code
            self.organizations = response.json()
            response.close()
            self.output_window.insertPlainText("[{0}] Populating organizations list...\n".format(timestamp))
            return result
        except Exception as e:
            return e

    '''
    Input:      str() -> Manager IP Address/FQDN ; str() -> API Key 
    Processing: HTTP Get request to test credentials via TestParams() ;
                Parse JSON encoded organizations into a graphical combination box (drop down) 
    Output:     Fully populated combiantion box / drop down menu with EDR tenant organization names
    '''
    @pyqtSlot()
    def SetParams(self):
        timestamp = time.ctime()
        dialogue  = QMessageBox.question(self, 'Parameter Confirmation', "Manager IP/FQDN: {0} \nAPI Key: {1} \nAre the address and key correct?".format(self.tenant_addr.text(),self.api_key.text()), QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if(dialogue == QMessageBox.Yes):
            self.mgr_address = self.tenant_addr
            self.api_key     = self.api_key
            mgr_set_str      = "[{0}] EDR API tenant set to: {1} \n".format(timestamp,self.mgr_address.text())
            key_set_str      = "[{0}] EDR API key set to: {1} \n".format(timestamp,self.api_key.text())
            self.output_window.insertPlainText(mgr_set_str)
            self.output_window.insertPlainText(key_set_str)
            self.output_window.insertPlainText("[{0}] Testing parameters...\n".format(timestamp))
            test_params_res  = self.TestParams()
            if(test_params_res == 200):
                self.output_window.insertPlainText("[{0}] Confirmed validity of API parameters...\n".format(timestamp))
                self.headers = {'X-Auth-Token': '{0}'.format(self.api_key.text())}
                self.output_window.insertPlainText("[{0}] Populating organizations list...\n".format(timestamp))
                #
                for org in self.organizations:
                    for entry in org.keys():
                        if(entry == 'name'):
                            self.output_window.insertPlainText("[{0}] Identified: {1} \n".format(timestamp,org[entry]))
                            self.org_combo_box.addItem(org[entry])
            else:
                self.output_window.insertPlainText("[{0}] Invalid API parameters entered...\n".format(timestamp))
                self.output_window.insertPlainText("[{0}] Server returned: {1}\n".format(timestamp,test_params_res))
        else:
            self.tenant_addr.setText("")
            self.api_key.setText("")

    '''
    Input:      str() -> Manager IP Address/FQDN ; str() -> API Key ; str() -> Current Organization
    Processing: Register drop down menu change event
                Transmit HTTP Get request to the API endpoint with the organization as the query term
                Retrieve a list of collectors for the organization
                Populate a combination box with all of the organization's collectors
                Populate a list with all of the organization's collectors
    Output:     Fully populate combination box and data structure with collector identities
    '''
    def RegisterOrganization(self):
        timestamp = time.ctime()
        self.current_organization = self.org_combo_box.currentText()
        self.output_window.insertPlainText("[{0}] Selected organization: {1}\n".format(timestamp,self.current_organization))
        try:
            ctr_url = "https://{0}/management-rest/inventory/list-collectors?organization={1}".format(self.mgr_address.text(),self.current_organization)
            self.output_window.insertPlainText("[{0}] Querying: {1}\n".format(timestamp,ctr_url))
            reg_response           = requests.get(ctr_url, headers=self.headers, timeout=3, verify=False)
            reg_result             = reg_response.status_code
            reg_response.close()
            if(reg_result == 200):
                self.collectors = reg_response.json()
                self.output_window.insertPlainText("[{0}] Populating collector inventory for: {1}\n".format(timestamp,self.current_organization))
                self.ctr_combo_box.clear()
                self.current_collectors = []
                if(len(self.collectors) > 0):
                    for collector in self.collectors:
                        for entry in collector.keys():
                            single_collector = collector
                            for value in single_collector.keys():
                                id   = single_collector['id']
                                name = single_collector['name']
                                collector_entry = str(id)+":"+name
                                if(collector_entry not in self.current_collectors):
                                    self.current_collectors.append(collector_entry)
                                    self.ctr_combo_box.addItem(collector_entry)
            else:
                self.output_window.insertPlainText("[{0}] Failed to locate any collectors for: {1}\n".format(timestamp,self.current_organization))
        except Exception as e:
            self.output_window.insertPlainText("[{0}] Error populating collector list: {1}\n".format(timestamp,e))

    '''
    Input:      None
    Processing: Purge Manager Address and API Key input fields
    Output:     Vacant text input fields
    '''
    @pyqtSlot()
    def ClearParams(self):
        timestamp = time.ctime()
        self.tenant_addr.setText("")
        self.api_key.setText("")
        self.output_window.insertPlainText("[{0}] Cleared parameters\n".format(timestamp))

    '''
    Input:      str() -> Manager IP Address/FQDN ; str() -> API Key ; str() -> collector
    Processing: Extract string value from the collector drop down menu
                Send HTTP PUT request to the API endpoint instructing the manager to isolate the collector/host
    Output:     Return text based indication of success or failure based on the response code
    '''
    def IsolateHost(self):
        timestamp      = time.ctime()
        ctr_entry      = self.ctr_combo_box.currentText()
        collector_id   = ctr_entry.split(':')[0]
        collector_name = ctr_entry.split(':')[1]
        dialogue       = QMessageBox.question(self, 'CAUTION', "Organization: {0} \nCollector ID: {1} \nCollector Name: {2} \nAre you certain you want to isolate this host?".format(self.current_organization,collector_id,collector_name, QMessageBox.Yes | QMessageBox.No, QMessageBox.No))
        #
        try:
            if(dialogue == QMessageBox.Yes):
                self.output_window.insertPlainText("[{0}] Confirmation received, attempting isolation of {1}:{2}...\n".format(timestamp,collector_id,collector_name))
                iso_url          = "https://{0}/management-rest/inventory/isolate-collectors?organization={1}&devicesIds={2}".format(self.mgr_address.text(),self.current_organization,collector_id)
                iso_response     = requests.put(iso_url, headers=self.headers, timeout=3, verify=False)
                if(iso_response.status_code == 200):
                    self.output_window.insertPlainText("[{0}] Successfully isolated {1}:{2} \n".format(timestamp,collector_id,collector_name))
                else:
                    self.output_window.insertPlainText("[{0}] Error -> Failed to isolate: {1} \n".format(timestamp,collector_name))
                self.output_window.insertPlainText("[{0}] Sent: {1}\n".format(timestamp,iso_url))
            else:
                self.output_window.insertPlainText("[{0}] Declined to isolate: {1}\n".format(timestamp,collector_name))
        except Exception as e:
            self.output_window.insertPlainText("[{0}] Error -> Failed to isolate: {1} : {2}\n".format(timestamp,collector_name,e))

    '''
    Input:      str() -> Manager IP Address/FQDN ; str() -> API Key ; str() -> collector
    Processing: Extract string value from the collector drop down menu
                Send HTTP PUT request to the API endpoint instructing the manager to unisolate the collector/host
    Output:     Return text based indication of success or failure based on the response code
    '''
    def RestoreHost(self):
        timestamp      = time.ctime()
        ctr_entry      = self.ctr_combo_box.currentText()
        collector_id   = ctr_entry.split(':')[0]
        collector_name = ctr_entry.split(':')[1]
        dialogue       = QMessageBox.question(self, 'CAUTION', "Organization: {0} \nCollector ID: {1} \nCollector Name: {2} \nAre you certain you want to unisolate this host?".format(self.current_organization,collector_id,collector_name, QMessageBox.Yes | QMessageBox.No, QMessageBox.No))
        #
        try:
            if(dialogue == QMessageBox.Yes):
                self.output_window.insertPlainText("[{0}] Confirmation received, attempting restoration of {1}:{2}...\n".format(timestamp,collector_id,collector_name))
                res_url          = "https://{0}/management-rest/inventory/unisolate-collectors?organization={1}&devicesIds={2}".format(self.mgr_address.text(),self.current_organization,collector_id)
                res_response     = requests.put(res_url, headers=self.headers, timeout=3, verify=False)
                if(res_response.status_code == 200):
                    self.output_window.insertPlainText("[{0}] Successfully unisolated {1}:{2} \n".format(timestamp,collector_id,collector_name))
                else:
                    self.output_window.insertPlainText("[{0}] Error -> Failed to unisolate: {1} \n".format(timestamp,collector_name))
                self.output_window.insertPlainText("[{0}] Sent: {1}\n".format(timestamp,res_url))
            else:
                self.output_window.insertPlainText("[{0}] Declined to unisolate: {1}\n".format(timestamp,collector_name))
        except Exception as e:
            self.output_window.insertPlainText("[{0}] Error -> Failed to unisolate: {1} : {2}\n".format(timestamp,collector_name,e))

    '''
    Input:      str() -> Manager IP Address/FQDN ; str() -> API Key ; str() -> Current Organization
    Processing: Extract string value from the collector drop down menu for the currently selected organization
                Send HTTP PUT request to the API endpoint instructing the manager to isolate each collector or host in the organization
    Output:     Return text based indication of success or failure based on the response code, for each host
    '''
    def IsolateOrganization(self):
        timestamp = time.ctime()
        self.output_window.insertPlainText("[{0}] Preparing to isolate collectors within: {1}\n".format(timestamp,self.current_organization))
        dialogue       = QMessageBox.question(self, 'CAUTION', "Organization Name: {} \nAre you certain you want to isolate this entire organization?".format(self.current_organization, QMessageBox.Yes | QMessageBox.No, QMessageBox.No))
        if(dialogue == QMessageBox.Yes):
            self.output_window.insertPlainText("[{0}] Confirmation received, attempting isolation collectors for: {1}...\n".format(timestamp,self.current_organization))
            try:
                if(len(self.current_collectors) > 0):
                    self.output_window.insertPlainText("[{0}] Isolating collectors for: {1}\n".format(timestamp,self.current_organization))
                    for collector in self.current_collectors:
                        collector_id     = collector.split(':')[0]
                        collector_name   = collector.split(':')[1]
                        self.output_window.insertPlainText("[{0}] Isolating: {1}\n".format(timestamp,collector_name))
                        ctr_iso_url          = "https://{0}/management-rest/inventory/isolate-collectors?organization={1}&devicesIds={2}".format(self.mgr_address.text(),self.current_organization,collector_id)
                        ctr_iso_response     = requests.put(ctr_iso_url, headers=self.headers, timeout=3, verify=False)
                        if(ctr_iso_response.status_code == 200):
                            self.output_window.insertPlainText("[{0}] Successfully isolated {1}:{2} \n".format(timestamp,collector_id,collector_name))
                        else:
                            self.output_window.insertPlainText("[{0}] Error -> Failed to isolate: {1} \n".format(timestamp,collector_name))
                else:
                    self.output_window.insertPlainText("[{0}] No collectors in the current inventory for: {1}\n".format(timestamp,self.current_organization))
            except Exception as e:
                self.output_window.insertPlainText("[{0}] Error -> Failed to isolate: {1} : {2}\n".format(timestamp,collector_name,e))
        else:
            self.output_window.insertPlainText("[{0}] Declined to isolate the organization: {1}\n".format(timestamp,self.current_organization))

    '''
    Input:      str() -> Manager IP Address/FQDN ; str() -> API Key ; str() -> Current Organization
    Processing: Extract string value from the collector drop down menu for the currently selected organization
                Send HTTP PUT request to the API endpoint instructing the manager to unisolate each collector or host in the organization
    Output:     Return text based indication of success or failure based on the response code, for each host
    '''
    def RestoreOrganization(self):
        timestamp = time.ctime()
        self.output_window.insertPlainText("[{0}] Preparing to restore collectors within: {1}\n".format(timestamp,self.current_organization))
        dialogue       = QMessageBox.question(self, 'CAUTION', "Organization Name: {} \nAre you certain you want to unisolate this entire organization?".format(self.current_organization, QMessageBox.Yes | QMessageBox.No, QMessageBox.No))
        if(dialogue == QMessageBox.Yes):
            try:
                if(len(self.current_collectors) > 0):
                    self.output_window.insertPlainText("[{0}] Unisolating collectors for: {1}\n".format(timestamp,self.current_organization))
                    for collector in self.current_collectors:
                        collector_id     = collector.split(':')[0]
                        collector_name   = collector.split(':')[1]
                        self.output_window.insertPlainText("[{0}] Unisolating: {1}\n".format(timestamp,collector))
                        ctr_res_url          = "https://{0}/management-rest/inventory/unisolate-collectors?organization={1}&devicesIds={2}".format(self.mgr_address.text(),self.current_organization,collector_id)
                        ctr_res_response     = requests.put(ctr_res_url, headers=self.headers, timeout=3, verify=False)
                        if(ctr_res_response.status_code == 200):
                            self.output_window.insertPlainText("[{0}] Successfully unisolated {1}:{2} \n".format(timestamp,collector_id,collector_name))
                        else:
                            self.output_window.insertPlainText("[{0}] Error -> Failed to unisolate: {1} \n".format(timestamp,collector_name))
                else:
                    self.output_window.insertPlainText("[{0}] No collectors in the current inventory for: {1}\n".format(timestamp,self.current_organization))
            except Exception as e:
                self.output_window.insertPlainText("[{0}] Error -> Failed to unisolate: {1} : {2}\n".format(timestamp,collector,e))
        else:
            self.output_window.insertPlainText("[{0}] Declined to unisolate the organization: {1}\n".format(timestamp,self.current_organization))

if(__name__ == '__main__'):
    app = QApplication(sys.argv)
    screen = Window()
    screen.show()
    sys.exit(app.exec_())
