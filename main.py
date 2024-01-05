#################### IMPORT ####################
# qt
from PyQt6 import QtCore, QtGui, QtWidgets, uic
from PyQt6.QtWidgets import (
    QApplication, 
    QWidget, 
    QFileDialog, 
    QGridLayout,
    QPushButton, 
    QLabel,
    QProgressBar,
    QMessageBox,
    QDialog
)
from PyQt6.QtCore import QThread, QProcess, pyqtSignal #threads

# python standard lib
import sys, os, json, time, logging, hashlib, math
from logging.handlers import RotatingFileHandler
import bcrypt


#################### FUNZIONI ####################
class MainWindow(QtWidgets.QMainWindow):

    working_dir = None        # percorso alla directory corrente
    config = None             # file di configurazione, dictionary caricato dal file config.json
    worker_thread = None      # worker thread che si occupa di fare l'hash dei file
    

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # setto variili della classe che mi possono essere utili
        self.working_dir = get_working_directory()
        set_working_directory()
        
        # carico il file creato con qt designer
        uic.loadUi("main.ui", self)


        # creo la cartella dei log se non esiste
        if not os.path.exists(os.path.join(self.working_dir,"logs")): 
            os.makedirs(os.path.join(self.working_dir,"logs")) 

        # imposto logging su file
        logging.basicConfig(
            # appendo log al file, non vado a sovrascrivere, non specifico filemode poichè di default è già append
            format='%(asctime)s - %(levelname)s - %(message)s'  # formato
            , level=logging.DEBUG
            , handlers=[
                #logging.FileHandler(LOG_FILENAME), # nome del file di log, di questo handler non ho bisogno poichè sul file disk scrive già RotatingFileHandler
                logging.StreamHandler(sys.stdout),  # quando vado a inserire un log stampo anche su console
                logging.handlers.RotatingFileHandler(os.path.join(self.working_dir,"logs","app.log"), maxBytes=1000000, backupCount=5, encoding='utf-8') # log rotating 1MB
            ]
        )
        logging.debug('*********************************************')
        logging.debug('Applicazione py_hash avviata')


        # carico il thread e definisco gli eventi 
        self.worker_thread = WorkerThread()
        self.worker_thread.sig_job_update.connect(self.thread_job_update)
        self.worker_thread.sig_job_complete.connect(self.thread_job_complete)
        self.worker_thread.sig_all_complete.connect(self.thread_all_complete)
        

        #self.config = readConfigJson()
        #machine = self.config["machine"]


        # modifico ulteriormente la gui poichè non riesco a fare tutto da qtdesigner
        self.changeUI()

        # setto gli eventi dei vari widgets
        self.settaEventi()
        
        
    
    # -------------------------------------------------------------------------------
    # modifica ulteriore della UI
    # -------------------------------------------------------------------------------
    def changeUI(self):
        
        #statusbar
        self.progressbar = QProgressBar() # nuova progress bar
        self.progressbar.setRange(0, 100) # valori possibili da 0 a 100
        self.progressbar.setTextVisible(True)  # posso modificare il testo della progress
        self.statusBar().addPermanentWidget(self.progressbar, 1) # la aggiungo alla status bar e faccio in modo che occupi tutto lo spazio disponibile
        
        # imposta l'icona della finestra
        self.setWindowIcon(QtGui.QIcon('icona.ico'))

    # -------------------------------------------------------------------------------
    # definizione degli eventi 
    # -------------------------------------------------------------------------------
    # entry per settare tutti gli eventi
    def settaEventi(self):
        pass
        # toolbar - Lancio i Job per calcolare l'hash
        self.actionRun_Hash.triggered.connect(self.hash_avvio_job) 
        # toolbar - esco dall'app
        self.actionExit.triggered.connect(self.close) 
        
        # devo scegliere dei files e popolare la textarea relativa
        self.pushButtonAddFiles.clicked.connect(self.addFiles) 

        
    # apro la modale per la scelta dei files e popolo la textarea relativa
    def addFiles(self):
        file_list = []
        dialog = QFileDialog(self)
        dialog.setDirectory(self.working_dir)
        dialog.setFileMode(QFileDialog.FileMode.ExistingFiles)
        #dialog.setNameFilter("Images (*.png *.jpg)")
        dialog.setViewMode(QFileDialog.ViewMode.List)
        if dialog.exec():
            # ritorno una lista di path assoluti 
            self.file_list = dialog.selectedFiles()
            
            #azzero la textarea
            self.plainTextEdit_FilesInput.clear()

            # aggiorno la textarea con i files selezionati
            for x in self.file_list:
                self.plainTextEdit_FilesInput.appendPlainText(x)
            
    # -------------------------------------------------------------------------------
    # Metodi per calcolare l'hash
    # -------------------------------------------------------------------------------
    # inizio il lavoro per calcolare l'hash di una stringa o di più files
    def hash_avvio_job(self):
        
        # recupero l'algoritmo scelto
        hash_algo_scelto = self.comboBoxHash.currentText()

        # mi calcolo quale tab è attivo e scelgo il metodo corretto da eseguire
        if self.tabWidget.currentIndex() == 0:
            
            # caso dell'hash di una stringa - solo testo

            # recupero la stringa inserita
            stringa = self.plainTextEdit_SrtingInput.toPlainText().strip().encode('utf-8')
            
            # variabile che conterrà l'hash
            convertita = ""

            # switch in base all'algoritmo
            if hash_algo_scelto == "bcrypt_password_for_php":
                # caso speciale per generare l'hash che digerisce php con la funzione password_verify()
                convertita = bcrypt.hashpw(stringa, bcrypt.gensalt()).decode("utf-8")
            else:
                # reupero l'oggetto che utilizzerò pr fare l'hash
                objhash = self.get_hash_obj()
                objhash.update(stringa)
                convertita = objhash.hexdigest()
                

            # inserisco la stringa convertita nella textarea
            self.plainTextEdit_SrtingResult.clear()
            self.plainTextEdit_SrtingResult.appendPlainText(convertita)
            

        else:
            # sono nel caso in cui devo fare l'hash di uno o più file

            if hash_algo_scelto == "bcrypt_password_for_php":
                # algoritmo non supportato per i files - cambiare algo
                QMessageBox.about(self, "Alert", "Algoritmo non supportato - prego cambiare algortimo")
                return
            

            # ripulisco la textarea che conterrà il risultato
            self.plainTextEdit_FilesResult.clear()

            # recupero la lista dei file dalla textarea
            file_list_temp = self.plainTextEdit_FilesInput.toPlainText().splitlines()
            file_list = []
            
            # filtro solo i file esistenti popolando file_list
            for path in file_list_temp:
                if os.path.isfile(path):
                    file_list.append(path)

            # controllo se i sono files da processare
            if len(file_list) > 0:

                # disabilito alcuni controlli nella ui
                self.plainTextEdit_FilesInput.setEnabled(False)
                self.pushButtonAddFiles.setEnabled(False)
                self.plainTextEdit_FilesResult.setEnabled(False)
                self.comboBoxHash.setEnabled(False)

                # passo argomenti al thread e lo lancio
                self.worker_thread.settaVar(file_list, self.get_hash_obj)
                self.worker_thread.start()

            else:
                QMessageBox.about(self, "Alert", "non ci sono file da processare, controlla che la textarea non sia vuota e che i percorsi contenuti siano dei files esistenti")

    
    # ritorno l'oggetto hash in base al valore selezionato dalla combo
    def get_hash_obj(self):
        hash_algo_scelto = self.comboBoxHash.currentText()
        obj = None
        if hash_algo_scelto == "md5":
            obj = hashlib.md5()
        elif hash_algo_scelto == "sha1":
            obj = hashlib.sha1()
        elif hash_algo_scelto == "sha224":
            obj = hashlib.sha224()
        elif hash_algo_scelto == "sha256":
            obj = hashlib.sha256()
        elif hash_algo_scelto == "sha384":
            obj = hashlib.sha384()
        elif hash_algo_scelto == "sha512":
            obj = hashlib.sha512()
        elif hash_algo_scelto == "sha3_224":
            obj = hashlib.sha3_224()
        elif hash_algo_scelto == "sha3_256":
            obj = hashlib.sha3_256()
        elif hash_algo_scelto == "sha3_384":
            obj = hashlib.sha3_384()
        elif hash_algo_scelto == "sha3_512":
            obj = hashlib.sha3_512()
        
        return obj    


    # -------------------------------------------------------------------------------
    # EVENTI del thread
    # -------------------------------------------------------------------------------
    # aggiornamento specifico relativo al calcolo dell'hash di un singolo file
    # da utilizzare con progress bar
    def thread_job_update(self, perc, path):
        self.progressbar.setValue(perc)  # imposto la percentuale
        self.progressbar.setFormat("calcolo " + path + " - " + str(perc) + "%")  # imposto la scritta della progress bar

    # ho completato il calcolo dell'hash di un file, vado a scrivere il risultato nella textarea
    def thread_job_complete(self, path, str_ex):
        self.progressbar.reset() # resetto la progress
        hash_algo_scelto = self.comboBoxHash.currentText() # recupero l'hash scelto

        # loggo nel log
        logging.debug(hash_algo_scelto + ": " + path)
        logging.debug(str_ex)

        # aggiorno la textarea con il risultato dell'hash del file
        self.plainTextEdit_FilesResult.appendPlainText(hash_algo_scelto + ": " + path + "\n" + str_ex + "\n")

    # ho finito il calcolo di tutti i files, riabilito i controlli disabilitati
    def thread_all_complete(self):
        self.progressbar.reset()
        self.plainTextEdit_FilesInput.setEnabled(True)
        self.pushButtonAddFiles.setEnabled(True)
        self.plainTextEdit_FilesResult.setEnabled(True)
        self.comboBoxHash.setEnabled(True)


class WorkerThread(QThread):

    # puntatori alle funzioni da chiamare nel thread principale
    sig_job_update = pyqtSignal(int, str)
    sig_job_complete = pyqtSignal(str, str)
    sig_all_complete = pyqtSignal()

    # variabili di appoggio
    file_list = []
    func_get_hash = None

    # mi passo alcune variabili prima di lanciare il thread
    def settaVar(self, file_list, func_get_hash):
        self.file_list = file_list
        self.func_get_hash = func_get_hash

    # si deve chiamare run i metodo
    # lo invoco nel thread principale (quello della ui) con il metodo .start()
    def run(self):
        # ciclo sui file
        for path in self.file_list:
            
            # mi ritorno l'oggeto hash n base alla combo selezionata
            objhash_temp = self.func_get_hash()

            # dimensione totale del file
            tot_size = os.path.getsize(path)
            
            # variabili di appogio
            bytesread = 0
            perc = 0
            
            with open(path,"rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096),b""):
                    # aggiorno l'oggetto hash in base ai bytes letti
                    objhash_temp.update(byte_block)

                    # blocco per calcolare la percentuale del lavoro
                    bytesread += len(byte_block)
                    perc_temp = math.floor((bytesread / tot_size) * 100)
                    if perc != perc_temp:
                        # percentuale aumentata - aggiorno il valore perc e la GUI
                        perc = perc_temp
                        self.sig_job_update.emit(perc, path)
                    

            # finito di calcolare l'hash di un file, aggiorno la gui
            str_ex = objhash_temp.hexdigest()
            self.sig_job_complete.emit(path, str_ex)
        
        # finito tutto
        self.sig_all_complete.emit()

    
    




# #leggo il file di config con tutti le configurazioni del programma
def readConfigJson():
    with open('config.json') as json_data_file:
        appsetting = json.load(json_data_file)
        return appsetting


def set_working_directory():
    absPath = get_working_directory()
    os.chdir(absPath)


def get_working_directory():
    absPath = ""
    # mi costruisco il percorso assoluto della directory che contiene il file main.py
    if(os.path.isabs(sys.argv[0])):
        absPath = os.path.dirname(sys.argv[0])
    else:
        #provo a costruirmi la directory in questo modo (sonogià dentro la directory del programma)
        absPath = os.path.dirname(os.path.abspath('.') + "/" + sys.argv[0])

    return absPath


# mi dice se sono un mac linux oppure windows
def get_os():
    os_name = "nix"
    if os.name == 'nt':
        os_name = "windows"
    return os_name



#################### ENTRY PROGRAMMA ####################
if __name__ == "__main__":
    #main(sys.argv[1:])
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()

'''
nomi dei widget presenti 


comboBoxHash
la combo per la scelta dell'hash

tabWidget
è il gruppo tab
currentIndex mi dice quale tab è settato

1 tab
    plainTextEdit_SrtingInput
    è la textarea che contiene la stringa dahashare

    plainTextEdit_SrtingResult
    è la textarea che contiene il testo hashato


2 tab
    plainTextEdit_FilesInput
    è la textara che contiene i percorsi assoluti dei file che devo hashare

    pushButtonAddFiles
    è il bottone che clicco per aggiungere files

    plainTextEdit_FilesResult
    è la textarea che contiene l'ash dei files


menu
    actionRun_Hash
    toolbar menu item che lancia l'ash job

    actionExit
    toolbar menu item mi fa uscire
'''
