from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import string
import hashlib
import utility
import os, ntpath, sys
from threading import Thread

class App:

    def __init__(self, master, parametro):
        self.master = master
        self.config_windows(master)
        self.isFile = False
        
        frame=ttk.Frame(master, padding='0 5 0 0') # padding è left nord west sud
        frame.grid(row=0, column=0, sticky=N+S+E+W)
        
        # mi dice quale colonna e resizable
        # in questo caso la prima colonna non si resiza (di defafult è così), laseconda colonna si resiza (weight=1)
        Grid.columnconfigure(frame, 1, weight=1) 
        
        # mi dice che l'utima row del frame deve occupare lo spazio (in verticale) quando faccio il resize della windows
        Grid.rowconfigure(frame, 3, weight=1)
        #Grid.columnconfigure(frame, 0, weight=1) #Grid.rowconfigure(frame, 1, weight=1)        
        
        self.create_menu(master)
        self.add_controlli(master, frame, parametro)
        self.create_statusBar(frame)
    
    def config_windows(self,master):
        # mpostazioni iniziali della finestra
        
        master.geometry('{}x{}'.format(700, 128)) #dimensione inziale
        master.minsize(700, 128)  #dimensione minima
        master.maxsize(1000, 128) #dimensione massima
        Grid.rowconfigure(master, 0, weight=1)
        Grid.columnconfigure(master, 0, weight=1)
    
    #creo il menu inziale - per il momento non fa nulla
    def create_menu(self, master):
        menu = Menu(master)
        master.config(menu=menu)

        # Voce File
        filemenu = Menu(menu, tearoff=False)
        menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="Open...", command=self.OpenFile)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=master.destroy)

        # Voce Comando
        comandomenu = Menu(menu, tearoff=False)
        menu.add_cascade(label="Comando", menu=comandomenu)
        comandomenu.add_command(label="Hash string", command=self.calcola_stringa)
        comandomenu.add_command(label="Hash file", command=self.calcola_file)
        
        # Voce Help
        helpmenu = Menu(menu, tearoff=False)
        menu.add_cascade(label="Help", menu=helpmenu)
        helpmenu.add_command(label="About...", command=self.About)

    def add_controlli(self, master, frame, parametro):
        mylist=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
        self.var = StringVar(master)
        self.var.set("md5") # initial value
        
        ttk.Label(frame, text="Stringa").grid(row=0, sticky=W, padx=5, pady=5)
        ttk.Label(frame, text="Type").grid(row=1, sticky=W, padx=5, pady=5)
        ttk.Label(frame, text="hash code").grid(row=2, sticky=W, padx=5, pady=5)
        
        self.e1 = ttk.Entry(frame)
        self.e2 = ttk.Entry(frame)
        self.omenu = ttk.OptionMenu(frame, self.var, *mylist)
        
        self.e1.grid(row=0, column=1, padx=5, pady=5, sticky=W+E)
        self.omenu.grid(row=1, column=1, padx=5, pady=5, sticky=W+E)
        #self.omenu..config(bg='white',width=60)
        self.e2.grid(row=2, column=1, padx=5, pady=5, sticky=W+E)
        #self.create_popup_for_entry(master,self.e3)
        #self.e3.bind("<Control-Key-c>", self.copy_all2)
        #self.e3.bind("<Control-Key-C>", self.copy_all2) # just in case caps lock is on
        
        if parametro is not None:
            self.e1.delete(0, END)
            self.e1.insert(0, parametro)
    
    def create_statusBar(self,frame):
        self.status_bar = ttk.Label(frame,background="#ffffff",relief=FLAT,text="  Stato ...")
        self.status_bar.grid(row=3, columnspan=2, sticky=S+W+E)
    
    # creo il popup per l'entry 3
    #def create_popup_for_entry(self, master, entry):
    #    self.popup = Menu(master, tearoff=0)
    #    self.popup.add_command(label="Copy", command=self.copy_all1) # , command=next) etc...
    #    #self.popup.add_separator()
    #    self.popup.add_command(label="nothing")
    #    entry.bind("<Button-3>", self.do_popup)
            
    #copio la stringa nella clip quando faccio ctrl + c
    #def copy_all2(self, event):
    #    self.master.clipboard_clear()
    #    self.master.clipboard_append(self.e3.get())
    
    #copio la stringa nella clip quando seleziono voce menu "Copy"
    #def copy_all1(self):
    #    self.master.clipboard_clear()
    #    self.master.clipboard_append(self.e3.get())

    # display the popup menu
    #def do_popup(self,event):
    #    try:
    #        self.popup.tk_popup(event.x_root, event.y_root, 0)
    #    finally:
    #        # make sure to release the grab (Tk 8.0a1 only)
    #        self.popup.grab_release()
            
    # http://stackoverflow.com/questions/3431825/generating-a-md5-checksum-of-a-file
    # calcolo l'hash di un file

    def calcola_file(self):
        t = Thread(target=self.calcola_file_thread)
        t.daemon = True # l'esecuzione di questo thread viene interrotta se il thread principale esce 
        t.start()
    
    def calcola_file_thread(self):
        pathfile = self.e1.get()
        tot_bytes = os.path.getsize(pathfile)
        m = self.get_type_of_hash()
        strout = self.hashfile(pathfile,m, tot_bytes)
        self.e2.delete(0, END)
        self.e2.insert(0, strout)
    
    def printStausOperation(self,pathfile,tot_bytes,processed_bytes):
        temp_number = 100 * processed_bytes / tot_bytes
        temp_stringa = "{0:.0f}".format(temp_number) + "%"
        nome_file = ntpath.basename(pathfile)
        self.status_bar["text"] = "  Hashing " + nome_file + " - " + temp_stringa + "% of 100%"
            

    def hashfile(self,pathfile,hasher,tot_bytes,blocksize=65536):
        processed_bytes = 0
        with open(pathfile,"rb") as afile:
            buf = afile.read(blocksize)
            while len(buf) > 0:
                hasher.update(buf)
                processed_bytes += len(buf)
                self.printStausOperation(pathfile,tot_bytes,processed_bytes)
                buf = afile.read(blocksize)
        return hasher.hexdigest()
        
        
    # calcolo hash della stringa inserita
    def calcola_stringa(self):
        str = self.e1.get()
        if str == "":
            messagebox.showinfo("Attenzione", "Stringa vuota - prego inserire stringa")
            return
            
        m = self.get_type_of_hash()
        m.update(str.encode('utf-8'))
        self.e2.delete(0, END)
        self.e2.insert(0, m.hexdigest())

    def get_type_of_hash(self):
        if self.var.get() == 'sha1':
            m = hashlib.sha1()
        elif self.var.get() == 'sha224':
            m = hashlib.sha224()
        elif self.var.get() == 'sha256':
            m = hashlib.sha256()
        elif self.var.get() == 'sha384':
            m = hashlib.sha384()
        elif self.var.get() == 'sha512':
            m = hashlib.sha512()
        else:
            m = hashlib.md5()
        return m
    
    def OpenFile(self):
        file_path = filedialog.askopenfilename()
        if file_path == "":
            messagebox.showinfo("Info", "Nessun file selezionato")
        else:
            self.e1.delete(0, END)
            self.e1.insert(0, file_path)
            self.status_bar["text"] = "  Stato ..."
            self.e2.delete(0, END)
            
        
    def About(self):
        messagebox.showinfo("Info", "Programma per il calcolo dell'hash di un file fisico o di una stringa\nEntrambi il percorso del file o la stringa sono prese dalla textbox \"stringa\" ")
    

def main(argv):
    
    if len(sys.argv) > 1:
        parametro = sys.argv[1] #prendo parametro passato
    else:
        parametro = None

    script_directory = utility.getScriptDirectory()
    
    root = Tk()
    root.wm_title("Hash String and File")
    app = App(root,parametro)
    print(script_directory + '\\icona.ico')
    root.iconbitmap(script_directory + '\\icona.ico')
    #root.iconbitmap('icona.ico')
    root.mainloop()
    
if __name__ == '__main__':
    main(sys.argv)


