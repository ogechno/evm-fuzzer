import csv

with open('opcode.csv', mode ='r')as file:
    csvFile = csv.reader(file)
    opcode = []
    name = []

    for lines in csvFile:
        opcode.append(lines[0][3:-1])
        name.append(lines[1])

    for i in range(len(opcode)):
        opcode[i] += '"'
        name[i] += '="'
        name[i] += opcode[i]
        print(name[i])
