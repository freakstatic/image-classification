# File-level ingest module for Autopsy to classify images
from java.lang import Integer
from java.util.logging import Level
from java.text import NumberFormat
from java.awt import Color
from java.awt import Toolkit
from java.awt import Dimension
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt.Dialog import ModalityType
from javax.swing import JPanel
from javax.swing import JDialog
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JFormattedTextField
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import SwingUtilities
from javax.swing.text import NumberFormatter

from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard

import inspect
import socket
import json
import struct
import io
import os, sys, subprocess

CONFIG_FILE_NAME = 'config.json'
DEFAULT_MIN_FILE_SIZE = 5
DEFAULT_MIN_PROBABILITY = 50
DEFAULT_IMAGES_FORMAT = "jpg;png;jpeg"
DEFAULT_PORT = 1337
DEFAULT_HOST = "127.0.0.1"
DEFAULT_CLASSES_OF_INTEREST = '[{"name":"person","enabled":true},{"name":"bicycle","enabled":true},{"name":"car","enabled":true},{"name":"motorbike","enabled":true},{"name":"aeroplane","enabled":true},{"name":"bus","enabled":true},{"name":"train","enabled":true},{"name":"truck","enabled":true},{"name":"boat","enabled":true},{"name":"traffic light","enabled":true},{"name":"fire hydrant","enabled":true},{"name":"stop sign","enabled":true},{"name":"parking meter","enabled":true},{"name":"bench","enabled":true},{"name":"bird","enabled":true},{"name":"cat","enabled":true},{"name":"dog","enabled":true},{"name":"horse","enabled":true},{"name":"sheep","enabled":true},{"name":"cow","enabled":true},{"name":"elephant","enabled":true},{"name":"bear","enabled":true},{"name":"zebra","enabled":true},{"name":"giraffe","enabled":true},{"name":"backpack","enabled":true},{"name":"umbrella","enabled":true},{"name":"handbag","enabled":true},{"name":"tie","enabled":true},{"name":"suitcase","enabled":true},{"name":"frisbee","enabled":true},{"name":"skis","enabled":true},{"name":"snowboard","enabled":true},{"name":"sports ball","enabled":true},{"name":"kite","enabled":true},{"name":"baseball bat","enabled":true},{"name":"baseball glove","enabled":true},{"name":"skateboard","enabled":true},{"name":"surfboard","enabled":true},{"name":"tennis racket","enabled":true},{"name":"bottle","enabled":true},{"name":"wine glass","enabled":true},{"name":"cup","enabled":true},{"name":"fork","enabled":true},{"name":"knife","enabled":true},{"name":"spoon","enabled":true},{"name":"bowl","enabled":true},{"name":"banana","enabled":true},{"name":"apple","enabled":true},{"name":"sandwich","enabled":true},{"name":"orange","enabled":true},{"name":"broccoli","enabled":true},{"name":"carrot","enabled":true},{"name":"hot dog","enabled":true},{"name":"pizza","enabled":true},{"name":"donut","enabled":true},{"name":"cake","enabled":true},{"name":"chair","enabled":true},{"name":"sofa","enabled":true},{"name":"pottedplant","enabled":true},{"name":"bed","enabled":true},{"name":"diningtable","enabled":true},{"name":"toilet","enabled":true},{"name":"tvmonitor","enabled":true},{"name":"laptop","enabled":true},{"name":"mouse","enabled":true},{"name":"remote","enabled":true},{"name":"keyboard","enabled":true},{"name":"cell phone","enabled":true},{"name":"microwave","enabled":true},{"name":"oven","enabled":true},{"name":"toaster","enabled":true},{"name":"sink","enabled":true},{"name":"refrigerator","enabled":true},{"name":"book","enabled":true},{"name":"clock","enabled":true},{"name":"vase","enabled":true},{"name":"scissors","enabled":true},{"name":"teddy bear","enabled":true},{"name":"hair drier","enabled":true},{"name":"toothbrush","enabled":true}]'


class AutopsyImageClassificationModuleFactory(IngestModuleFactoryAdapter):
    # give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Image Classification"

    def __init__(self):
        self.settings = None

    def getModuleDisplayName(self):
        return self.moduleName

    # Give it a description
    def getModuleDescription(self):
        return "This module uses YOLO Object Detection System to classify images"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return AutopsyImageClassificationModule(self.settings)

    def getDefaultIngestJobSettings(self):
        return AutopsyImageClassificationModuleWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, AutopsyImageClassificationModuleWithUISettings):
            err_1 = "Expected 'settings' argument to be" \
                    "'AutopsyImageClassificationModuleWithUISettings'"
            raise IngestModuleException(err_1)
        self.settings = settings
        return AutopsyImageClassificationModuleWithUISettingsPanel(self.settings)


class AutopsyImageClassificationModule(FileIngestModule):
    _logger = Logger.getLogger(AutopsyImageClassificationModuleFactory.moduleName)
    MAX_CHUNK_SIZE = 1024

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context
        if not self.local_settings.isServerOnline():
            raise IngestModuleException(IngestModule(), "Server is down!")
            pass
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    def process(self, file):
        # Skip non-files
        if is_non_file(file):
            return IngestModule.ProcessResult.OK

        file_name = file.getName().lower()
        if not self.is_image(file_name):
            return IngestModule.ProcessResult.OK

        self.log(Level.INFO, 'Processing ' + file.getLocalAbsPath())

        detections = self.get_detections(file.getLocalAbsPath())

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        if isinstance(detections, list):
            if len(detections) == 0:
                self.create_an_artifact(blackboard, file, "No known objects found")
            else:
                for detection in detections:
                    # only report the detections with high probability
                    if detection["probability"] >= self.local_settings.getMinProbability():
                        for classes in self.local_settings.getClassesOfInterest():
                            if detection['className'] == classes['name'] and classes['enabled']:
                                self.create_an_artifact(blackboard, file, detection["className"].title())
                                break

        else:
            self.log(Level.INFO,
                     'Error classifying image ' + file.getLocalAbsPath() + ' with error code: ' + detections[
                         'errorCode'] + 'and message: ' + detections['errorMessage'])
            self.create_an_artifact(blackboard, file, "ERROR - Processed with errors")

        self.log(Level.INFO, 'Finish...')
        # lock.release()
        return IngestModule.ProcessResult.OK

    def create_an_artifact(self, blackboard, file, title):

        art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
        att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                  AutopsyImageClassificationModuleFactory.moduleName,
                                  title)
        art.addAttribute(att)
        try:
            # index the artifact for keyword search
            blackboard.indexArtifact(art)
        except Blackboard.BlackboardException as e:
            self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        # Fire an event to notify the UI and others that there is a new artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(AutopsyImageClassificationModuleFactory.moduleName,
                            BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT))

    def get_detections(self, file_path):
        # Connect the socket
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.connect((self.local_settings.getServerHost(), int(self.local_settings.getServerPort())))

        filename, file_extension = os.path.splitext(file_path)
        new_socket.sendall(file_extension)
        self.receive_an_int_message(new_socket)

        # get file size
        file_size = os.path.getsize(file_path)
        new_socket.sendall(file_size)
        self.receive_an_int_message(new_socket)

        self.send_image_and_get_data(new_socket, file_path, file_size)
        ack_status = self.receive_an_int_message(new_socket)

        while ack_status == -1:
            self.log(Level.INFO, "Re-send image: " + file_path)
            self.send_image_and_get_data(new_socket, file_path, file_size)
            ack_status = self.receive_an_int_message(new_socket)

        return_value = None
        new_socket.sendall(1)

        nr_of_bytes_to_receive = self.receive_an_int_message(new_socket)
        self.log(Level.INFO, "Received nr of bytes: " + str(nr_of_bytes_to_receive))

        new_socket.sendall(1)
        # If there are no detections we can return now
        if nr_of_bytes_to_receive == 0:
            return_value = IngestModule.ProcessResult.OK
        elif nr_of_bytes_to_receive > 0:
            response = new_socket.recv(nr_of_bytes_to_receive)
            while len(response) < nr_of_bytes_to_receive:
                data = new_socket.recv(nr_of_bytes_to_receive - len(response))
                if not data:
                    break
                response += data
            self.log(Level.INFO, "Received from image: " + file_path + "the response: " + response)
            return_value = json.loads(response)
        new_socket.close()
        return return_value

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        None

    def receive_an_int_message(self, my_socket):
        bytes_received = my_socket.recv(4)
        ack_response = struct.unpack("!i", bytes_received)[0]
        return ack_response

    def send_image_and_get_data(self, new_socket, file_path, file_size):
        # send file
        with open(file_path, 'rb') as f:
            file_readed_left = file_size
            file_chunk = self.MAX_CHUNK_SIZE
            while file_readed_left > 0:
                if file_readed_left < self.MAX_CHUNK_SIZE:
                    file_chunk = file_readed_left
                new_socket.sendall(f.read(file_chunk))
                file_readed_left = file_readed_left - file_chunk

    def is_image(self, file_name):

        valid = False
        for image_format in self.local_settings.getImageFormats():
            if file_name.endswith("." + image_format):
                valid = True

        return valid


class AutopsyImageClassificationModuleWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        # Note: on Autopsy 4.4.1, the jython interpreter complains
        # about the non existence of the self.m_insert_duplicate flag.
        self.m_insert_duplicate = None

        self.server_host = ""
        self.server_port = ""
        self.image_formats = ""
        self.min_file_size = 0
        self.min_probability = 0
        self.classes_of_interest = []
        self.server_online = False

    def getServerHost(self):
        return self.server_host

    def getServerPort(self):
        return self.server_port

    def getImageFormats(self):
        return self.image_formats

    def getMinFileSize(self):
        return self.min_file_size

    def getMinProbability(self):
        return self.min_probability

    def getVersionNumber(self):
        return self.serialVersionUID

    def isServerOnline(self):
        return self.server_online

    def getClassesOfInterest(self):
        return self.classes_of_interest

    def setServerHost(self, server_host):
        self.server_host = server_host

    def setServerPort(self, port):
        self.server_port = port

    def setImageFormats(self, image_formats):
        self.image_formats = image_formats

    def setMinFileSize(self, min_file_size):
        self.min_file_size = min_file_size

    def setMinProbability(self, min_probability):
        self.min_probability = min_probability

    def setIsServerOnline(self, is_server_online):
        self.server_online = is_server_online

    def setClassesOfInterest(self, classes_of_interest):
        self.classes_of_interest = classes_of_interest


class AutopsyImageClassificationModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    _logger = Logger.getLogger(AutopsyImageClassificationModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.local_settings = settings
        self.config_location = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'configs.json')
        self.init_components()
        self.customize_components()
        self.check_server_connection(None)
        self.classes_of_interest_changes_list = list()
        self.classes_of_interest_checkboxes = list()

    # Return the settings used
    def getSettings(self):
        if not os.path.isfile(self.config_location):
            self.log(Level.INFO, "Configuration file not found, loading the default configuration")
            self.local_settings.setServerHost(DEFAULT_HOST)
            self.local_settings.setServerPort(DEFAULT_PORT)
            self.local_settings.setImageFormats(DEFAULT_IMAGES_FORMAT)
            self.local_settings.setMinFileSize(DEFAULT_MIN_FILE_SIZE)
            self.local_settings.setMinProbability(DEFAULT_MIN_PROBABILITY)
            self.local_settings.setClassesOfInterest(json.loads(DEFAULT_CLASSES_OF_INTEREST))
            # self.saveSettings(None)
            return self.local_settings
        else:
            if not os.access(self.config_location, os.R_OK):
                err_string = "Cannot access configuration file, please review the file permissions"
                raise IngestModuleException(err_string)

            with io.open(self.config_location, 'r', encoding='utf-8') as f:
                self.log(Level.INFO, "Configuration file read")
                json_configs = json.load(f)

            self.local_settings.setServerHost(json_configs['server']['host'])
            self.local_settings.setServerPort(json_configs['server']['port'])

            image_formats = json_configs['imageFormats']

            if not isinstance(image_formats, list) or len(image_formats) == 0:
                err_string = "Invalid list of image formats given"
                raise IngestModuleException(err_string)

            self.local_settings.setImageFormats(image_formats)

            self.local_settings.setMinFileSize(json_configs['minFileSize'])
            self.local_settings.setMinProbability(json_configs['minProbability'])
            self.local_settings.setClassesOfInterest(json_configs['classesOfInterest'])
            return self.local_settings

    def check_server_connection(self, e):
        message_string = "Testing connection with server..."
        self.log(Level.INFO, message_string)
        self.message.setText(message_string)
        self.error_message.setText("")

        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.settimeout(1)
        try:
            new_socket.connect((self.host_TF.getText(), int(self.port_TF.getText())))
            self.local_settings.setIsServerOnline(True)
            message_string = "Server is up!"
            self.log(Level.INFO, message_string)
            self.message.setText(message_string)

        except (socket.timeout, socket.error) as e:
            self.local_settings.setIsServerOnline(False)
            err_string = "Server is down"
            self.error_message.setText(err_string)
            self.message.setText("")
            self.log(Level.INFO, err_string)
        finally:
            new_socket.close()

    def save_settings(self, e):
        self.message.setText("")
        self.log(Level.INFO, "Settings save button clicked!")

        host = self.host_TF.getText()

        if not host.strip():
            err_string = "Invalid host"
            self.error_message.setText(err_string)
            return
            # raise IngestModuleException(err_string)

        port = self.port_TF.getText()
        if not host.strip():
            err_string = "Invalid port number"
            self.error_message.setText(err_string)
            return
            # raise IngestModuleException(err_string)

        image_formats_array = self.image_formats_TF.getText().strip().split(';')
        if len(image_formats_array) == 0 or not image_formats_array[0]:
            err_string = "Invalid image formats"
            self.error_message.setText(err_string)
            return
            # raise IngestModuleException(err_string)

        min_probability_string = self.min_probability_TF.getText().strip()
        if not min_probability_string:
            err_string = "Invalid minimum confidence value"
            self.error_message.setText(err_string)
            return
            # raise IngestModuleException(err_string)

        min_probability = int(float(min_probability_string))

        min_file_size_string = self.min_file_size_TF.getText().strip()
        if not min_file_size_string:
            err_string = "Invalid minimum file size"
            self.error_message.setText(err_string)
            return
            # raise IngestModuleException(err_string)

        min_file_size = int(float(min_file_size_string))

        configs = {
            'server': {
                'host': host,
                'port': port
            },
            'imageFormats': image_formats_array,
            'minProbability': min_probability,
            'minFileSize': min_file_size,
            'classesOfInterest': self.local_settings.getClassesOfInterest()
        }

        with io.open(self.config_location, 'w', encoding='utf-8') as f:
            f.write(json.dumps(configs, ensure_ascii=False))

        self.error_message.setText("")

        message = "Settings saved "
        self.message.setText(message)
        self.log(Level.INFO, message + " in " + self.config_location)

    def open_text_editor(self, e):
        self.log(Level.INFO, "Lauching external text editor ")
        if sys.platform == "win32":
            subprocess.call(["notepad", self.config_location])
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            subprocess.call([opener, self.config_location])

    def on_save_classes_of_interest_click(self, e):
        self.detectable_obejcts_dialog.setVisible(False)
        for item in self.classes_of_interest_changes_list:
            for class_oi in self.local_settings.getClassesOfInterest():
                if item.getText() == class_oi['name']:
                    self.log(Level.INFO,
                             "match found " + class_oi['name'] + " and is selected " + str(item.isSelected()))
                    class_oi['enabled'] = item.isSelected()
                    break
        self.classes_of_interest_checkboxes = list()

    def on_cancel_classes_of_interest_click(self, e):
        self.detectable_obejcts_dialog.setVisible(False)
        self.classes_of_interest_changes_list = list()
        self.classes_of_interest_checkboxes = list()

    def on_class_checkbox_clicked(self, e):
        self.classes_of_interest_changes_list.append(e.getSource())

    def on_select_all_clicked(self, e):
        for checkbox in self.classes_of_interest_checkboxes:
            checkbox.setSelected(True)

    def on_deselect_all_clicked(self, e):
        for checkbox in self.classes_of_interest_checkboxes:
            checkbox.setSelected(False)

    def show_detectable_objects_dialog(self, e):
        parentComponent = SwingUtilities.windowForComponent(self.panel0)
        self.detectable_obejcts_dialog = JDialog(parentComponent, "List of Objects to Detect",
                                                 ModalityType.APPLICATION_MODAL)
        panel = JPanel()
        self.detectable_obejcts_dialog.add(panel)
        gbPanel = GridBagLayout()
        gbcPanel = GridBagConstraints()
        panel.setLayout(gbPanel)

        y = 0
        x = 0
        for line in self.local_settings.getClassesOfInterest():
            if y > 15:
                y = 0
                x = x + 1

            class_check_box = JCheckBox(line['name'])
            self.classes_of_interest_checkboxes.append(class_check_box)
            class_check_box.setEnabled(True)
            class_check_box.setSelected(line['enabled'])
            class_check_box.addItemListener(self.on_class_checkbox_clicked)
            gbcPanel.gridx = x
            gbcPanel.gridy = y
            gbcPanel.gridwidth = 1
            gbcPanel.gridheight = 1
            gbcPanel.fill = GridBagConstraints.BOTH
            gbcPanel.weightx = 1
            gbcPanel.weighty = 1
            gbcPanel.anchor = GridBagConstraints.NORTH
            gbPanel.setConstraints(class_check_box, gbcPanel)
            panel.add(class_check_box)
            y = y + 1

        blank_1_L = JLabel(" ")
        blank_1_L.setEnabled(True)
        gbcPanel.gridx = 0
        gbcPanel.gridy = y + 1
        gbcPanel.gridwidth = 1
        gbcPanel.gridheight = 1
        gbcPanel.fill = GridBagConstraints.BOTH
        gbcPanel.weightx = 1
        gbcPanel.weighty = 0
        gbcPanel.anchor = GridBagConstraints.NORTH
        gbPanel.setConstraints(blank_1_L, gbcPanel)
        panel.add(blank_1_L)

        deselect_all_button = JButton("Deselect all")
        deselect_all_button.setEnabled(True)
        deselect_all_button.addActionListener(self.on_deselect_all_clicked)
        gbcPanel.gridx = 1
        gbcPanel.gridy = y + 2
        gbcPanel.gridwidth = 1
        gbcPanel.gridheight = 1
        gbcPanel.fill = GridBagConstraints.BOTH
        gbcPanel.weightx = 2
        gbcPanel.weighty = 1
        gbcPanel.anchor = GridBagConstraints.NORTH
        gbPanel.setConstraints(deselect_all_button, gbcPanel)
        panel.add(deselect_all_button)

        select_all_button = JButton("Select all")
        select_all_button.setEnabled(True)
        select_all_button.addActionListener(self.on_select_all_clicked)
        gbcPanel.gridx = 3
        gbcPanel.gridy = y + 2
        gbcPanel.gridwidth = 1
        gbcPanel.gridheight = 1
        gbcPanel.fill = GridBagConstraints.BOTH
        gbcPanel.weightx = 2
        gbcPanel.weighty = 1
        gbcPanel.anchor = GridBagConstraints.NORTH
        gbPanel.setConstraints(select_all_button, gbcPanel)
        panel.add(select_all_button)

        blank_2_L = JLabel(" ")
        blank_2_L.setEnabled(True)
        gbcPanel.gridx = 0
        gbcPanel.gridy = y + 3
        gbcPanel.gridwidth = 1
        gbcPanel.gridheight = 1
        gbcPanel.fill = GridBagConstraints.BOTH
        gbcPanel.weightx = 1
        gbcPanel.weighty = 0
        gbcPanel.anchor = GridBagConstraints.NORTH
        gbPanel.setConstraints(blank_2_L, gbcPanel)
        panel.add(blank_2_L)

        cancel_button = JButton("Cancel")
        cancel_button.setEnabled(True)
        cancel_button.addActionListener(self.on_cancel_classes_of_interest_click)
        gbcPanel.gridx = 1
        gbcPanel.gridy = y + 4
        gbcPanel.gridwidth = 1
        gbcPanel.gridheight = 1
        gbcPanel.fill = GridBagConstraints.BOTH
        gbcPanel.weightx = 2
        gbcPanel.weighty = 1
        gbcPanel.anchor = GridBagConstraints.NORTH
        gbPanel.setConstraints(cancel_button, gbcPanel)
        panel.add(cancel_button)


        save_button = JButton("Save")
        save_button.setEnabled(True)
        save_button.addActionListener(self.on_save_classes_of_interest_click)
        gbcPanel.gridx = 3
        gbcPanel.gridy = y + 4
        gbcPanel.gridwidth = 1
        gbcPanel.gridheight = 1
        gbcPanel.fill = GridBagConstraints.BOTH
        gbcPanel.weightx = 2
        gbcPanel.weighty = 1
        gbcPanel.anchor = GridBagConstraints.NORTH
        gbPanel.setConstraints(save_button, gbcPanel)
        panel.add(save_button)

        blank_3_L = JLabel(" ")
        blank_3_L.setEnabled(True)
        gbcPanel.gridx = 0
        gbcPanel.gridy = y + 5
        gbcPanel.gridwidth = 1
        gbcPanel.gridheight = 1
        gbcPanel.fill = GridBagConstraints.BOTH
        gbcPanel.weightx = 1
        gbcPanel.weighty = 0
        gbcPanel.anchor = GridBagConstraints.NORTH
        gbPanel.setConstraints(blank_3_L, gbcPanel)
        panel.add(blank_3_L)

        self.detectable_obejcts_dialog.pack()
        screenSize = Toolkit.getDefaultToolkit().getScreenSize()
        self.detectable_obejcts_dialog.setLocation(
            int((screenSize.getWidth() / 2) - (self.detectable_obejcts_dialog.getWidth() / 2)),
            int((screenSize.getHeight() / 2) - (self.detectable_obejcts_dialog.getHeight() / 2)))
        self.detectable_obejcts_dialog.setVisible(True)

    def customize_components(self):
        settings = self.getSettings()

        self.host_TF.setText(settings.getServerHost())
        self.port_TF.setText(str(settings.getServerPort()))
        self.log(Level.INFO, "[customizeComponents]")

        self.log(Level.INFO, settings.getImageFormats()[0])
        self.image_formats_TF.setText(';'.join(settings.getImageFormats()))
        self.min_probability_TF.setText(str(settings.getMinProbability()))
        self.min_file_size_TF.setText(str(settings.getMinFileSize()))

    def init_components(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup()
        self.gbPanel0 = GridBagLayout()
        self.gbcPanel0 = GridBagConstraints()
        self.panel0.setLayout(self.gbPanel0)

        self.host_L = JLabel("Host:")
        self.host_L.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 1
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.host_L, self.gbcPanel0)
        self.panel0.add(self.host_L)

        self.port_L = JLabel("Port:")
        self.port_L.setEnabled(True)
        self.gbcPanel0.gridx = 1
        self.gbcPanel0.gridy = 1
        self.gbcPanel0.gridwidth = 2
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.port_L, self.gbcPanel0)
        self.panel0.add(self.port_L)

        self.host_TF = JTextField(10)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 2
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.host_TF, self.gbcPanel0)
        self.panel0.add(self.host_TF)

        format = NumberFormat.getInstance()
        format.setGroupingUsed(False)

        port_formatter = NumberFormatter(format)
        port_formatter.setValueClass(Integer)
        port_formatter.setAllowsInvalid(False)
        port_formatter.setMinimum(Integer(0))
        port_formatter.setMaximum(Integer(65535))

        self.port_TF = JFormattedTextField(port_formatter)
        self.gbcPanel0.gridx = 1
        self.gbcPanel0.gridy = 2
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.port_TF, self.gbcPanel0)
        self.panel0.add(self.port_TF)

        self.blank_1_L = JLabel(" ")
        self.blank_1_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 3
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_1_L, self.gbcPanel0)
        self.panel0.add(self.blank_1_L)

        self.image_formats_L = JLabel("Format of images (separator \";\"):")
        self.port_L.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 4
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.image_formats_L, self.gbcPanel0)
        self.panel0.add(self.image_formats_L)

        self.image_formats_TF = JTextField(10)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.image_formats_TF, self.gbcPanel0)
        self.panel0.add(self.image_formats_TF)

        self.blank_2_L = JLabel(" ")
        self.blank_2_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 6
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_2_L, self.gbcPanel0)
        self.panel0.add(self.blank_2_L)

        self.min_probability_L = JLabel("Confidence minimum (%):")
        self.port_L.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 7
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_probability_L, self.gbcPanel0)
        self.panel0.add(self.min_probability_L)

        min_probabilty_formatter = NumberFormatter(format)
        min_probabilty_formatter.setValueClass(Integer)
        min_probabilty_formatter.setAllowsInvalid(False)
        min_probabilty_formatter.setMinimum(Integer(0))
        min_probabilty_formatter.setMaximum(Integer(100))

        self.min_probability_TF = JFormattedTextField(min_probabilty_formatter)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 8
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_probability_TF, self.gbcPanel0)
        self.panel0.add(self.min_probability_TF)

        self.blank_3_L = JLabel(" ")
        self.blank_3_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 9
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_3_L, self.gbcPanel0)
        self.panel0.add(self.blank_3_L)

        self.min_file_size_L = JLabel("Minimum file size (KB):")
        self.min_file_size_L.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 10
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_file_size_L, self.gbcPanel0)
        self.panel0.add(self.min_file_size_L)

        min_file_size_formatter = NumberFormatter(format)
        min_file_size_formatter.setValueClass(Integer)
        min_file_size_formatter.setAllowsInvalid(False)
        min_file_size_formatter.setMinimum(Integer(0))

        self.min_file_size_TF = JFormattedTextField(min_file_size_formatter)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_file_size_TF, self.gbcPanel0)
        self.panel0.add(self.min_file_size_TF)

        self.blank_4_L = JLabel(" ")
        self.blank_4_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 12
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_4_L, self.gbcPanel0)
        self.panel0.add(self.blank_4_L)

        self.detectable_obejcts_BTN = \
            JButton("List of Objects to Detect", actionPerformed=self.show_detectable_objects_dialog)
        # self.save_Settings_BTN.setPreferredSize(Dimension(1, 20))
        self.rbgPanel0.add(self.detectable_obejcts_BTN)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 13
        self.gbPanel0.setConstraints(self.detectable_obejcts_BTN, self.gbcPanel0)
        self.panel0.add(self.detectable_obejcts_BTN)

        self.blank_5_L = JLabel(" ")
        self.blank_5_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 14
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_5_L, self.gbcPanel0)
        self.panel0.add(self.blank_5_L)

        self.error_message = JLabel("", JLabel.CENTER)
        self.error_message.setForeground(Color.red)
        self.error_message.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 15
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.error_message, self.gbcPanel0)
        self.panel0.add(self.error_message)

        self.message = JLabel("", JLabel.CENTER)
        self.message.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 16
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.message, self.gbcPanel0)
        self.panel0.add(self.message)

        self.save_settings_BTN = JButton("Save Settings", actionPerformed=self.save_settings)
        # self.save_Settings_BTN.setPreferredSize(Dimension(1, 20))
        self.rbgPanel0.add(self.save_settings_BTN)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 17
        self.gbPanel0.setConstraints(self.save_settings_BTN, self.gbcPanel0)
        self.panel0.add(self.save_settings_BTN)

        self.blank_6_L = JLabel(" ")
        self.blank_6_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 18
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_6_L, self.gbcPanel0)
        self.panel0.add(self.blank_6_L)

        self.blank_7_L = JLabel(" ")
        self.blank_7_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_7_L, self.gbcPanel0)
        self.panel0.add(self.blank_7_L)

        self.check_server_connection_BTN = \
            JButton("Check server connection", actionPerformed=self.check_server_connection)
        # self.save_Settings_BTN.setPreferredSize(Dimension(1, 20))
        self.rbgPanel0.add(self.check_server_connection_BTN)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 20
        self.gbPanel0.setConstraints(self.check_server_connection_BTN, self.gbcPanel0)
        self.panel0.add(self.check_server_connection_BTN)

        self.blank_8_L = JLabel(" ")
        self.blank_8_L.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 21
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.blank_8_L, self.gbcPanel0)
        self.panel0.add(self.blank_8_L)

        self.text_editor_BTN = \
            JButton("Open config file", actionPerformed=self.open_text_editor)
        # self.save_Settings_BTN.setPreferredSize(Dimension(1, 20))
        self.rbgPanel0.add(self.text_editor_BTN)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 22
        self.gbPanel0.setConstraints(self.text_editor_BTN, self.gbcPanel0)
        self.panel0.add(self.text_editor_BTN)

        self.add(self.panel0)


def is_non_file(file):
    return ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False))
