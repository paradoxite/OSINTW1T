import csv

name = "brohala"
with open('retrieved-xss.csv', 'r') as csv_file:
    csv_reader = csv.reader(csv_file)
    with open(f'{name}-tweets.csv', 'w') as new_file:
        csv_writer = csv.writer(new_file, delimiter=",")
        for line in csv_reader:
            if line[11] == "en":
                csv_writer.writerow(line[10].split(","))
                
            

with open ('results.csv', 'w') as outcsv:
    csv_writer = csv.writer(outcsv)
    csv_writer.writerow(['Class', 'No. Retrieved', 'No. Identified'])
