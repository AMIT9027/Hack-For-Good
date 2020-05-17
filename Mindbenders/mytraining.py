import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
import pickle






def Splits(data,ratio):
    np.random.seed(42)
    shuffled=np.random.permutation(len(data))
    test_set_size=int(len(data)*ratio)
    test_indices=shuffled[:test_set_size]
    train_indices=shuffled[test_set_size:]
    return data.iloc[test_indices],data.iloc[train_indices]
    





if __name__=="__main__":
    pds=pd.read_csv(r'C:\\Users\\acer\\Desktop\\web data collect\\DATA.csv')
    train,test=Splits(pds,0.2)
    X_train=train[['FEVER','AGE','RUNNYNOSE','DIFF BREATH','BODYPAIN']].to_numpy()
    X_test=test[['FEVER','AGE','RUNNYNOSE','DIFF BREATH','BODYPAIN']].to_numpy()

    Y_train=train[['INFECTION']].to_numpy().reshape(1742,)
    Y_test=test[['INFECTION']].to_numpy().reshape(6972,)
    clf=LogisticRegression()
    clf.fit(X_train,Y_train)
    file=open('model.pkl','wb')
    pickle.dump(clf,file)
    file.close()
  