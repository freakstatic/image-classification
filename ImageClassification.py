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

HOST = "127.0.0.1"
PORT = 1337

class AutopsyImageClassificationModuleFactory(IngestModuleFactoryAdapter):
    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Image Classification"

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
        return AutopsyImageClassificationModule()


class AutopsyImageClassificationModule(FileIngestModule):
    _logger = Logger.getLogger(AutopsyImageClassificationModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
                (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        file_name = file.getName().lower()
        # lock = threading.Lock()
        # lock.acquire()

        if file_name.endswith(".png") or file_name.endswith(".jpg") or file_name.endswith(".jpeg"):

            self.log(Level.INFO, 'Processing ' + file.getLocalAbsPath())

            # Connect the socket
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_socket.connect((HOST, PORT))

            new_socket.sendall(file.getLocalAbsPath())

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

            detections = json.loads(response)

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
            new_socket.close()
            self.log(Level.INFO, 'Finish...')
        # lock.release()

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):

        None
