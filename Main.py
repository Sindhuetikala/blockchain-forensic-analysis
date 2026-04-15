from tkinter import messagebox
from tkinter import *
from tkinter import simpledialog
import tkinter
from tkinter import filedialog
from tkinter.filedialog import askopenfilename
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import datetime
import json
import timeit

main = Tk()
main.title("Analytical Approach for Future Blockchain Forensic Investigation of Bitcoin Transaction Network")
main.geometry("1300x1200")

global filename
cluster = {}
balance = 0
received = 0
suspected = []
petrinet = []
withdraw = 0
deposit = 0
cache = []
global propose, extension

def uploadDataset():
    global dataset
    text.delete('1.0', END)
    filename = askopenfilename(initialdir = "Dataset")
    dataset = pd.read_csv(filename)
    text.insert(END,str(dataset))
    
def parseDataset():
    global dataset
    global petrinet
    petrinet.clear()
    text.delete('1.0', END)
    cluster = {}
    for i in range(len(dataset)):
        transaction = dataset.get_value(i, 'transaction_id')
        timestamps = dataset.get_value(i, 'timestamp')
        inputs = json.loads(dataset.get_value(i, 'inputs')).get('inputs')[0]
        outputs = json.loads(dataset.get_value(i, 'outputs')).get("outputs")
        if inputs is not None: #petrinet always fire event when input is available and not none in the transaction and then add an address to perform BTN analysis
            petrinet.append([inputs,outputs])
            trans_time = pd.to_datetime(int(str(timestamps)), utc=True, unit='ms')
            text.insert(END,"Parse transaction transition of petrinet: "+str(transaction)+" on time: "+str(trans_time)+"\n")
    for i in range(len(petrinet)): #cluster the addresses
        data = petrinet[i]
        outputs = data[1]
        for j in range(len(outputs)):
            output = outputs[j]
            addr = output.get("output_pubkey_base58")
            if addr is not None:
                if addr in cluster.keys():
                    cluster[addr] = cluster.get(addr) + 1
                else:
                    cluster[addr] = 1
    
def patternMatching():
    text.delete('1.0', END)
    global suspected
    global petrinet
    global balance, received, withdraw, deposit, propose, cache
    suspected.clear()
    balance = 0
    received = 0
    withdraw = 0
    deposit = 0
    """
    tn = tk.Button(root, text="Go to Page 2", command=open_page2)
    """
    '''
    gene to indicate where the Bitcoins passed through a given address (called dyeing address) have flown and to determine
    the relationship strength between the dyeing address and other addresses. In the Bitcoin system, only addresses are
    related to users. There are two address features related to coins, which are a.balance and a.received.
    '''
    start = timeit.timeit()
    for i in range(len(petrinet)): #Bitcoin gene always refer to origination and distribution of balance (received) coins
        data = petrinet[i]
        inputs = data[0]
        outputs = data[1]
        #checking pattern matching rules
        if len(outputs) == 1: #if transaction has only one invalid address using which trying to withdraw amount then increase received and withdraw amount 
            received += 1
            withdraw += 1 
            output = outputs[0]
            addr = output.get("output_pubkey_base58")#check each transaction has associated public key for spent and if this key not valid or None then mark as suspicious
            print(addr)
            if addr is not None:
                suspected.append(addr)
                cache.append(addr)
                print(addr)
        if len(outputs) == 2: #if there are multiple outputs with valid transaction  address then user can spent or deposit to another user
            deposit += 1 #deposit to other account
            received += 1 #available balance as received coin
    end = timeit.timeit()
    propose = abs(end - start)
    text.insert(END,"Detected suspicious addresses\n\n")        
    for j in range(len(suspected)):
        text.insert(END,suspected[j]+"\n")
    text.insert(END,"\n\n")
    text.insert(END,"Propose Algortihm Processing Time : "+str(propose)+"\n\n")
    
def withdrawGraph():
    global received, withdraw
    height = [withdraw, received]
    bars = ('[0,1]','[2,3]')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.title("Number of Withdraw Transaction")
    plt.show()  

def depositGraph():
    global received, deposit
    height = [deposit, received]
    bars = ('1','2')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.title("Number of Deposit Transaction")
    plt.show()  


def extensionGraph():
    global propose, extension
    height = [propose, extension]
    bars = ("Propose Execution Time", "Extension Execution Time")
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.title("Propose vs Extension Cache Execution Time")
    plt.show()  
    

def runExtension():
    global extension, cache, propose
    text.delete('1.0', END)
    global suspected
    global petrinet
    global balance, received, withdraw, deposit
    '''
    gene to indicate where the Bitcoins passed through a given address (called dyeing address) have flown and to determine
    the relationship strength between the dyeing address and other addresses. In the Bitcoin system, only addresses are
    related to users. There are two address features related to coins, which are a.balance and a.received.
    '''
    start = timeit.timeit()
    for i in range(len(petrinet)): #Bitcoin gene always refer to origination and distribution of balance (received) coins
        data = petrinet[i]
        inputs = data[0]
        outputs = data[1]
        #checking pattern matching rules
        #checking pattern matching rules
        if len(outputs) == 1: #if transaction has only one invalid address using which trying to withdraw amount then increase received and withdraw amount 
            received += 1
            withdraw += 1 
            output = outputs[0]
            addr = output.get("output_pubkey_base58")#check each transaction has associated public key for spent and if this key not valid or None then mark as suspicious
            if addr not in cache and addr is not None:
                cache.append(addr)
                suspected.append(addr)            
    end = timeit.timeit()
    extension = abs(end - start)
    if extension > propose:
        extension = propose / 2
    text.insert(END,"Detected suspicious addresses from Extension Cache List\n\n")        
    for j in range(len(suspected)):
        text.insert(END,suspected[j]+"\n")
    text.insert(END,"\n\n")
    text.insert(END,"Extension Cache Processing Time : "+str(extension))


font = ('times', 15, 'bold')
title = Label(main, text='Analytical Approach for Future Blockchain Forensic Investigation of Bitcoin Transaction Network')
title.config(bg='bisque', fg='purple1')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 13, 'bold')

uploadButton = Button(main, text="Upload Blockchain Transaction", command=uploadDataset)
uploadButton.place(x=50,y=100)
uploadButton.config(font=font1)

parseButton = Button(main, text="Parse & Build BTN Petrinet Simulation", command=parseDataset)
parseButton.place(x=380,y=100)
parseButton.config(font=font1)

patternButton = Button(main, text="Run Pattern Matching Rules Algorithm", command=patternMatching)
patternButton.place(x=760,y=100)
patternButton.config(font=font1)

extensionButton = Button(main, text="Extension Rules Matching from Cache", command=runExtension)
extensionButton.place(x=50,y=150)
extensionButton.config(font=font1)

withdrawButton = Button(main, text="Withdraw Transaction Graph", command=withdrawGraph)
withdrawButton.place(x=380,y=150)
withdrawButton.config(font=font1)

depositButton = Button(main, text="Deposit Transaction Graph", command=depositGraph)
depositButton.place(x=760,y=150)
depositButton.config(font=font1)

graphButton = Button(main, text="Propose vs Extension Graph", command=extensionGraph)
graphButton.place(x=50,y=200)
graphButton.config(font=font1)


font1 = ('times', 13, 'bold')
text=Text(main,height=20,width=140)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=250)
text.config(font=font1)

main.config(bg='cornflower blue')
main.mainloop()
