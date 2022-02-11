# Python script using Scikit-learn
# for Decision Tree Classifier
 
# JSON
import json

# Import pandas for data structures
import pandas

# Sample Decision Tree Classifier
# from sklearn import datasets
from sklearn import metrics
from sklearn.tree import DecisionTreeClassifier

from sklearn.model_selection import train_test_split
 
# Global Variables
data = {}

# Imports data
# -Takes a file name/location
# -Returns nothing(modifies a global variable)
def importData(_fileName):
    print
    data = pandas.read_json(_fileName)
    data2 = pandas.json_normalize(data)
    #data.dropna(inplace=True)
    #data.drop_duplicates(inplace=True)

    # Train/Test split
    #X, y = data.content, data.language
    #X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Model params
    token_pattern = r"""(\b[A-Za-z_]\w*\b|[!\#\$%\&\*\+:\-\./<=>\?@\\\^_\|\~]+|[ \t\(\),;\{\}\[\]`"'])"""

    with open(_fileName, 'r') as handle:
        parsed = json.load(handle)
    #print(json.dumps(parsed, indent=4, sort_keys=True))
    print(data)
    print(data2)
    df = pandas.DataFrame(data)
    print(df)

# Main function
# -Takes 
# -Returns
def runClassifier():
    # Split data into training and testing sets

    # load the iris datasets
    dataset = datasets.load_iris()
    
    # fit a CART model to the data
    model = DecisionTreeClassifier()
    model.fit(dataset.data, dataset.target)
    print(model)
    
    # make predictions
    expected = dataset.target
    predicted = model.predict(dataset.data)
    
    # summarize the fit of the model
    print(metrics.classification_report(expected, predicted))
    print(metrics.confusion_matrix(expected, predicted))

if __name__ == "__main__":
    #runClassifier()
    print(importData("babyData.json"))