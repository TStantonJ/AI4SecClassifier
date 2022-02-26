# Python script using Scikit-learn
# for Decision Tree Classifier
import sys
import os
import json
import gzip
from pathlib import Path
import re

from sklearn import svm
from sklearn.model_selection import train_test_split
 

# Global Variables
good_data = []
bad_data = []

data = []
labels = []

# Import data
good_data_file = './classifierFiles/goodData.gz'
bad_data_file = './classifierFiles/badData.gz'

# Taken in both good and bad files and put them in seperate arrays
good_in_handle = gzip.open(good_data_file, 'r')
bad_in_handle = gzip.open(bad_data_file, 'r')

for line in good_in_handle:
    line = line.decode('utf-8')
    line = line.rstrip("\n")
    data_array = line.split(',')
    for item in range(len(data_array)):
        data_array[item] = int(data_array[item])
    good_data.append(data_array)

for line in bad_in_handle:
    line = line.decode('utf-8')
    line = line.rstrip("\n")
    data_array = line.split(',')
    for item in range(len(data_array)):
        data_array[item] = int(data_array[item])
    bad_data.append(data_array)


# Create equal length of good and bad data(This is cheating and bad but for testing only)
data_len = min(len(good_data),len(bad_data))

for i in range(data_len):
    data.append(good_data[i])
    data.append(bad_data[i])

    labels.append(0)
    labels.append(1)

#print(labels)
#print(data)

# ---Model Section---
# Create training and testing sets
train_data,test_data,train_labels,test_labels = train_test_split(data,labels,test_size=0.20)

# Train and test model
model = svm.SVC()
model.fit(train_data, train_labels) 

results = model.predict(test_data)


# Output Testing Results
correct = 0
incorrect = 0
for i in range(len(test_data)):
    if results[i] == test_labels[i]:
        correct += 1
    else:
        incorrect += 1

print('Correct: ', correct)
print('Incorrect: ', incorrect)
