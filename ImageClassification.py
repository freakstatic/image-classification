# File-level ingest module for Autopsy to classify images

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.autopsy.datamodel import BlackboardArtifactNode
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
import socket

import json
import threading
import struct
import io
import os

from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JList
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JComboBox


class AutopsyImageClassificationModuleFactory(IngestModuleFactoryAdapter):
    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Image Classification"

    def __init__(self):
        self.settings = None

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
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
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
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

        file_size_kb = file.getSize() / 1024

        if file_size_kb < long(float(self.local_settings.getMinFileSize())):
            self.log(Level.INFO,
                     "File " + file.getLocalAbsPath() + " ignored because of size under the minimun(" + self.local_settings.getMinFileSize() + "): " +
                     str(file_size_kb))
            return IngestModule.ProcessResult.OK

        self.log(Level.INFO, 'Processing ' + file.getLocalAbsPath())

        detections = self.get_detections(file.getLocalAbsPath())

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        for detection in detections:

            # only report the detections with high probability
            if detection["probability"] < self.local_settings.getMinProbability():
                return IngestModule.ProcessResult.OK

            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # artifact.  Refer to the developer docs for other examples.
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                      AutopsyImageClassificationModuleFactory.moduleName,
                                      detection["className"].title())
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

        self.log(Level.INFO, 'Finish...')
        # lock.release()

        return IngestModule.ProcessResult.OK

    def get_detections(self, file_path):
        # Connect the socket
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log(Level.INFO, '--------------------')
        self.log(Level.INFO, "Server " + self.local_settings.getServerHost() + ":"
                 + self.local_settings.getServerPort())

        new_socket.connect((self.local_settings.getServerHost(), int(self.local_settings.getServerPort())))

        new_socket.sendall(file_path)

        # Receive the size of the JSON with the detections
        bytes_received = new_socket.recv(4)
        nr_of_bytes_to_receive = struct.unpack("!i", bytes_received)[0]

        # If there are no detections we can return now
        if nr_of_bytes_to_receive == 0:
            return IngestModule.ProcessResult.OK

        self.log(Level.INFO, "I will receive: " + str(nr_of_bytes_to_receive))
        response = new_socket.recv(nr_of_bytes_to_receive)

        # Keep receiving the bytes until the JSON is completed (TCP can split the packages)
        while len(response) < nr_of_bytes_to_receive:
            self.log(Level.INFO, "Receiving: " + str(len(response)) + " of " + str(nr_of_bytes_to_receive)
                     + " bytes")
            response += new_socket.recv(nr_of_bytes_to_receive)

        self.log(Level.INFO, "Received: " + response)
        new_socket.close()
        return json.loads(response)

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):

        None

    def is_image(self, file_name):

        valid = False
        for image_format in self.local_settings.getImageFormats():
            if file_name.endswith("." + image_format):
                valid = True

        return valid


class AutopsyImageClassificationModuleWithUISettings(IngestModuleIngestJobSettings):

    def __init__(self):
        self.serialVersionUID = 1L
        # Note: on Autopsy 4.4.1, the jython interpreter complains
        # about the non existence of the self.m_insert_duplicate flag.
        self.m_insert_duplicate = None

        self.server_host = ""
        self.server_port = ""
        self.image_formats = ""
        self.min_file_size = 0
        self.min_probability = 0

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


class AutopsyImageClassificationModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    _logger = Logger.getLogger(AutopsyImageClassificationModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.local_settings = settings
        self.config_location = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'configs.json')
        self.initComponents()
        self.customizeComponents()

    # Return the settings used

    def getSettings(self):
        with io.open(self.config_location, 'r', encoding='utf-8') as f:
            self.log(Level.INFO, "Settings file read")
            json_configs = json.load(f)

        self.local_settings.setServerHost(json_configs['server']['host'])
        self.local_settings.setServerPort(json_configs['server']['port'])

        image_formats = json_configs['imageFormats']

        if not isinstance(image_formats, list) or len(image_formats) == 0:
            err_2 = "Invalid list of image formats given"
            raise IngestModuleException(err_2)

        self.local_settings.setImageFormats(image_formats)

        self.local_settings.setMinFileSize(json_configs['minFileSize'])
        self.local_settings.setMinProbability(json_configs['minProbability'])

        return self.local_settings
        # return True

    def saveSettings(self, e):
        self.log(Level.INFO, "Settings save button clicked!")

        image_formats_array = self.image_formats_TF.getText().split(';')

        configs = {
            'server': {
                'host': self.host_TF.getText(),
                'port': self.port_TF.getText()
            },
            'imageFormats': image_formats_array,
            'minProbability': self.min_probability_TE.getText(),
            'minFileSize': self.min_file_size_TE.getText()
        }

        with io.open(self.config_location, 'w', encoding='utf-8') as f:
            f.write(json.dumps(configs, ensure_ascii=False))

        self.log(Level.INFO, "Settings saved in " + self.config_location)

    def customizeComponents(self):
        settings = self.getSettings()

        self.host_TF.setText(settings.getServerHost())
        self.port_TF.setText(settings.getServerPort())
        self.log(Level.INFO, "[customizeComponents]")

        self.log(Level.INFO, settings.getImageFormats()[0])
        self.image_formats_TF.setText(';'.join(settings.getImageFormats()))
        self.min_probability_TE.setText(settings.getMinProbability())
        self.min_file_size_TE.setText(settings.getMinFileSize())

    def initComponents(self):
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
        self.gbcPanel0.gridwidth = 1
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

        self.port_TF = JTextField(5)
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

        self.min_probability_TE = JTextField(10)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 8
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_probability_TE, self.gbcPanel0)
        self.panel0.add(self.min_probability_TE)

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

        self.min_file_size_TE = JTextField(10)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_file_size_TE, self.gbcPanel0)
        self.panel0.add(self.min_file_size_TE)

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

        self.save_settings_BTN = \
            JButton("Save Settings", actionPerformed=self.saveSettings)
        # self.save_Settings_BTN.setPreferredSize(Dimension(1, 20))
        self.rbgPanel0.add(self.save_settings_BTN)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 15
        self.gbPanel0.setConstraints(self.save_settings_BTN, self.gbcPanel0)
        self.panel0.add(self.save_settings_BTN)

        self.add(self.panel0)


def is_non_file(file):
    return ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False))
