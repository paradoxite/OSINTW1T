from tkinter import *
from tkinter import ttk, font
import twint
from subprocess import Popen, PIPE
import csv
import spacy
from pathlib import Path
import tkinter.font as tkFont

def writeToCSV(fileRetrieved, vulnClass):
      tweetCounter = 0
      with open (fileRetrieved, 'r') as csv_file:
         csv_reader = csv.reader(csv_file)
         with open (f'{vulnClass}-English.csv', 'w') as newFile:
            csv_writer = csv.writer(newFile, delimiter=',')
            for line in csv_reader:
                if line[11] == "en":
                    tweetCounter += 1
                    csv_writer.writerow(line[10].split(','))
      return tweetCounter
    


def nerStats(tweetFile, vulnClass, retrievedCount):
    model = Path.cwd() / 'OSINTWIT_NER'
    print("Loading from", model)
    nlp = spacy.load(model)
    tweetCounter = 0
    with open (tweetFile, 'r') as tweets:    
        csv_reader = csv.reader(tweets)    

        for tweet in csv_reader:
            tweet = str(tweet)
            doc = nlp(tweet)
            for ent in doc.ents:
                if ent.label_ != None:  
                    tweetCounter += 1
                    with open (f'{vulnClass}-identified.csv', 'a') as validTweets:
                        csv_writer = csv.writer(validTweets, delimiter=',')
                        csv_writer.writerow(tweet.split(','))
        with open ('results.csv', 'a') as results:
            csv_writer = csv.writer(results, delimiter=',')
            csv_writer.writerow([vulnClass, retrievedCount, tweetCounter])
    return tweetCounter


def giveMeStats():
    #search_terms = open('search-terms.txt', 'w')
    info.insert(END, "Output:- ")
    info.insert(END,'\nFrom: ')
    info.insert(END, date1_entry.get())
    info.insert(END,'\nTo:')
    info.insert(END, date2_entry.get())
    
    if(chk_xss_state.get() == 1):
        xss_c = twint.Config()
        xss_c.Search = '"xss" OR "cross-site script"'
        xss_c.Since = date1_entry.get()
        xss_c.Until = date2_entry.get()
        xss_c.Min_likes = 5
        xss_c.Store_csv = True
        xss_c.Output = "retrieved-xss.csv"
        xss_c.Lang = 'en'
        twint.run.Search(xss_c)
        writeToCSV(xss_c.Output, "XSS")
        retrievedCount = writeToCSV(xss_c.Output, "XSS")
        identifiedCounter = nerStats("XSS-English.csv", "XSS", retrievedCount)
        info.insert(END, f'\nCross-site script {retrievedCount} Found & {identifiedCounter} Identified')
        
    if(chk_CSRF_state.get() == 1):
        csrf_c = twint.Config()
        csrf_c.Search = '"csrf" OR "cross-site request forgery"'
        csrf_c.Since = date1_entry.get()
        csrf_c.Until = date2_entry.get()
        csrf_c.Min_likes = 5
        csrf_c.Store_csv = True
        csrf_c.Output = "retrieved-csrf.csv"
        csrf_c.Lang = 'en'
        twint.run.Search(csrf_c)
        retrievedCount = writeToCSV(csrf_c.Output, "CSRF")
        identifiedCounter = nerStats("CSRF-English.csv", "CSRF", retrievedCount)
        info.insert(END, f'\nCross-site Request Forgery {retrievedCount} & {identifiedCounter} Identified')
        
    if(chk_unknown_state.get() == 1):
        unknown_c = twint.Config()
        unknown_c.Search = '"unknown" AND "vulnerability"'
        unknown_c.Since = date1_entry.get()
        unknown_c.Until = date2_entry.get()
        unknown_c.Min_likes = 5
        unknown_c.Store_csv = True
        unknown_c.Output = "retrieved-unknown.csv"
        unknown_c.Lang = 'en'
        twint.run.Search(unknown_c)
        retrievedCount = writeToCSV(unknown_c.Output, "UNKNOWN")
        identifiedCounter = nerStats("UNKNOWN-English.csv", "UNKNOWN", retrievedCount)
        info.insert(END, f'\nUnkown vulnerabilities {retrievedCount} Found & {identifiedCounter} Identified')
        
    if(chk_dos_state.get() == 1):
        dos_c = twint.Config()
        dos_c.Search = '"denial of service" OR "DOS"'
        dos_c.Since = date1_entry.get()
        dos_c.Until = date2_entry.get()
        dos_c.Min_likes = 5
        dos_c.Store_csv = True
        dos_c.Output = "retrieved-dos.csv"
        dos_c.Lang = 'en'
        twint.run.Search(dos_c)
        retrievedCount = writeToCSV(dos_c.Output, "DOS")
        identifiedCounter = nerStats("DOS-English.csv", "DOS", retrievedCount)
        info.insert(END, f'\nDenial of Service {retrievedCount} Found & {identifiedCounter} Identified')
        
    if(chk_finclusion_state.get() == 1):
        inclusion_c = twint.Config()
        inclusion_c.Search = '"file" AND "inclusion"'
        inclusion_c.Since = date1_entry.get()
        inclusion_c.Until = date2_entry.get()
        inclusion_c.Min_likes = 5
        inclusion_c.Store_csv = True
        inclusion_c.Output = "retrieved-inclusion.csv"
        inclusion_c.Lang = 'en'
        twint.run.Search(inclusion_c)
        retrievedCount = writeToCSV(inclusion_c.Output, "FI")
        identifiedCounter = nerStats("FI-English.csv", "FI", retrievedCount)
        info.insert(END, f'\nFile Inclusions(FI) {retrievedCount} Found & {identifiedCounter} Identified')
        
    if(chk_spoof_state.get() == 1):
        spoof_c = twint.Config()
        spoof_c.Search = 'spoof'
        spoof_c.Since = date1_entry.get()
        spoof_c.Until = date2_entry.get()
        spoof_c.Min_likes = 5
        spoof_c.Store_csv = True
        spoof_c.Output = "retrieved-spoof.csv"
        spoof_c.Lang = 'en'
        twint.run.Search(spoof_c)
        retrievedCount = writeToCSV(spoof_c.Output, "SPOOF")
        identifiedCounter = nerStats("SPOOF-English.csv", "SPOOF", retrievedCount)
        info.insert(END, f'\nSpoofs {retrievedCount} Found & {identifiedCounter} Identified')
            
    if(chk_bypass_state.get() == 1):
        bypass_c = twint.Config()
        bypass_c.Search = '"security" AND "bypass"'
        bypass_c.Since = date1_entry.get()
        bypass_c.Until = date2_entry.get()
        bypass_c.Min_likes = 5
        bypass_c.Store_csv = True
        bypass_c.Output = "retrieved-bypass.csv"
        bypass_c.Lang = 'en'
        twint.run.Search(bypass_c)
        retrievedCount = writeToCSV(bypass_c.Output, "BYPASS")
        identifiedCounter = nerStats("BYPASS-English.csv", "BYPASS", retrievedCount)
        info.insert(END, f'\nSecurity control bypasses {retrievedCount} Found & {identifiedCounter} Identified')
        
        
        
    """
    #twint configs
    search_terms = open('search-terms.txt', 'r')
    search_terms = search_terms.read()
    search_string = str(search_terms) + 'OR @iut8735iu235'
    config = twint.Config()
    config.Search = search_string
    config.Since = date1_entry.get()
    config.Until = date2_entry.get()
    config.Limit = 100
    config.Min_likes = 5
    config.Output = "retrieved.txt"
    #config.Pandas_clean = 1
    config.Lang = "en"
    twint.run.Search(config) 
    """

window2 = Tk()
window2.title("OSINTWIT")
fname = "logo.gif"
bg_image = PhotoImage(file=fname)
w = bg_image.width() -  70
h = bg_image.height()
window2.geometry("%dx%d+50+50" % (w,h+600))


cv = Canvas(width=w, height=h)
cv.pack(side='top', fill='both', expand='yes')
cv.create_image(0, 0, image=bg_image, anchor='nw')
font1 = tkFont.Font(family="MyriadPro-LightCond", weight="bold", size=13)
window2.configure(bg="White")
lbl1 = Label(window2, text="Pick Desired Classes", font=font1, bg='grey12', fg='#1DA1F2')
lbl1.place(x=10, y=5)

font2 = tkFont.Font(family="MyriadPro", size=10)
chk_xss_state = IntVar()
xss_chk = Checkbutton(window2, text="XSS", var=chk_xss_state,  fg="#1DA1F2", bg="white", onvalue=1, offvalue=0)
xss_chk['font'] = font2
xss_chk.place(x= 10, y=250)

chk_CSRF_state = IntVar()
CSRF_chk = Checkbutton(window2, text="CSRF", var=chk_CSRF_state, fg="#1DA1F2", bg='white', onvalue=1, offvalue=0)
CSRF_chk['font'] = font2
CSRF_chk.place(x=10, y=180)

chk_unknown_state = IntVar()
unknown_chk = Checkbutton(window2, text="Unknown", var=chk_unknown_state, fg="#1DA1F2", bg="White", onvalue=1, offvalue=0)
unknown_chk['font'] = font2
unknown_chk.place(x=10, y=75)

chk_dos_state = IntVar()
dos_chk = Checkbutton(window2, text="DOS", var=chk_dos_state, fg="#1DA1F2", bg='White', onvalue=1, offvalue=0)
dos_chk['font'] = font2
dos_chk.place(x=10, y=215)

chk_finclusion_state = IntVar()
finclusion_chk = Checkbutton(window2, text="File Inclusion", var=chk_finclusion_state, fg="#1DA1F2", bg="white", onvalue=1, offvalue=0)
finclusion_chk['font'] = font2
finclusion_chk.place(x=10, y=40)

chk_spoof_state = IntVar()
spoof_chk = Checkbutton(window2, text="Spoof", var=chk_spoof_state, fg="#1DA1F2", bg='White', onvalue=1, offvalue=0)
spoof_chk['font'] = font2
spoof_chk.place(x=10, y=145)

chk_bypass_state = IntVar()
bypass_chk = Checkbutton(window2, text="Bypasses", var=chk_bypass_state, fg="#1DA1F2", bg="white", onvalue=1, offvalue=0)
bypass_chk['font'] = font2
bypass_chk.place(x=10, y=110)



date1_label = Label(window2, text='Pick date (From)', font=("Arial Bold",10), bg="#1DA1F2", fg="White")
date1_entry = Entry(window2, width=10, bg="White", fg="Black")
date1_label.place(x= 150, y=305)
date1_entry.place(x=265, y=305)

font3 = tkFont.Font(weight='bold')
date2_label = Label(window2, text='Pick date (To)', font=("Arial Bold",10), bg="#1DA1F2", fg="White")
date2_entry = Entry(window2, width=10, bg="White", fg="Black")
date2_label.place(x= 380, y=305)
date2_entry.place(x=480, y=305)
go_button = Button(window2, text='GIVE ME SOME STATS', fg="White", bg="#1DA1F2", command=giveMeStats)
go_button['font'] = font3
go_button.place(x=235, y=350)

info = Text(window2, width=80, height=11, bg="White", fg='grey12')
info.place(x=5, y=420)  

with open ('results.csv', 'w') as outcsv:
        csv_writer = csv.writer(outcsv, delimiter=',')
        csv_writer.writerow(['Class', 'No. Retrieved', 'No. Identified'])
        


window2.mainloop()







"""
window = Tk()

window.title("OSINTWIT")
window.configure(bg="White")
window.geometry('360x200')
lbl0 = Label(window, text="What would you like to do?", font=("Poppins",20),bg="White", fg='#1DA1F2')
lbl0.grid(column=0, row=0)
btn0 = Button(window, text="Get statistics", bg="White", fg="#1DA1F2", command=statClick)
btn0.place(x=10, y=50)

btn1 = Button(window, text="Search for software", bg="White", fg="#1DA1F2")
btn1.place(x= 150, y=50)
"""



