import spacy
from pathlib import Path
import csv

model = Path.cwd() / 'OSINTWIT_NER'
print("Loading from", model)
nlp = spacy.load(model)
with open ('XSS-identified.csv', 'r') as tweets:
    csv_reader = csv.reader(tweets)
    for tweet in csv_reader:
        tweet = str(tweet)
        doc = nlp(tweet)
        for ent in doc.ents:
            if ent.label_ != None:
                print(ent.label_)
