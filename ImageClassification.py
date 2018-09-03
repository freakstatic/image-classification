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

from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import Dimension
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JList
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JComboBox

HOST = "127.0.0.1"
PORT = 1337


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
            Err_S = "Expected 'settings' argument to be" \
                    "'AutopsyImageClassificationModuleWithUISettings'"
            raise IngestModuleException(Err_S)
        self.settings = settings
        return AutopsyImageClassificationModuleWithUISettingsPanel(self.settings)


class AutopsyImageClassificationModule(FileIngestModule):
    _logger = Logger.getLogger(AutopsyImageClassificationModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):

        # Skip non-files
        if self.is_non_file(file):
            return IngestModule.ProcessResult.OK

        file_name = file.getName().lower()
        # lock = threading.Lock()
        # lock.acquire()

        if not is_image(file_name):
            return IngestModule.ProcessResult.OK

        self.log(Level.INFO, 'Processing ' + file.getLocalAbsPath())

        detections = self.get_detections(file.getLocalAbsPath())

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        for detection in detections:

            # only report the detections with high probability
            if detection["probability"] < 80:
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
        new_socket.connect((HOST, PORT))

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


class AutopsyImageClassificationModuleWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        # Note: on Autopsy 4.4.1, the jython interpreter complains
        # about the non existence of the self.m_insert_duplicate flag.
        self.m_insert_duplicate = None

    def getVersionNumber(self):
        return serialVersionUID


class AutopsyImageClassificationModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):

    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def checkBoxEvent(self, event):
        pass

    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup()
        self.gbPanel0 = GridBagLayout()
        self.gbcPanel0 = GridBagConstraints()
        self.panel0.setLayout(self.gbPanel0)

        self.port_L = JLabel("Host:")
        self.port_L.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 1
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.port_L, self.gbcPanel0)
        self.panel0.add(self.port_L)

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

        self.port_L = JLabel("Format of images to process (separator \";\"):")
        self.port_L.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 4
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.port_L, self.gbcPanel0)
        self.panel0.add(self.port_L)

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

        self.port_L = JLabel("Confidence minimum (%):")
        self.port_L.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 7
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.port_L, self.gbcPanel0)
        self.panel0.add(self.port_L)

        self.min_probability = JTextField(10)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 8
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_probability, self.gbcPanel0)
        self.panel0.add(self.min_probability)

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

        self.min_probability_TE = JTextField(10)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints(self.min_probability_TE, self.gbcPanel0)
        self.panel0.add(self.min_probability_TE)

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

        self.save_Settings_BTN = \
            JButton("Save Settings", actionPerformed=self.save_settings)
        self.save_Settings_BTN.setPreferredSize(Dimension(1, 20))
        self.save_Settings_BTN.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 15
        self.gbPanel0.setConstraints(self.save_Settings_BTN, self.gbcPanel0)
        self.panel0.add(self.save_Settings_BTN)

        self.add(self.panel0)
    def customizeComponents(self):
        pass

    # Return the settings used


    def getSettings(self):
        return self.local_settings

    def save_settings(self):
        return True

def is_image(file_name):
    return file_name.endswith(".png") or file_name.endswith(".jpg") or file_name.endswith(".jpeg")


def is_non_file(file):
    return ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False))
